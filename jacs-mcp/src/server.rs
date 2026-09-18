use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs_core::{agent::CoreAgent, sign::SigningAlgorithm};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
    Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use zeroize::Zeroizing;

use crate::{contract, vault};

pub const MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum Profile {
    #[default]
    VerifyOnly,
    LocalSign,
}

impl Profile {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "verify-only" => Ok(Self::VerifyOnly),
            "local-sign" => Ok(Self::LocalSign),
            _ => Err("expected exactly verify-only or local-sign"),
        }
    }
    pub fn resolve(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            Some(value) => Self::parse(value),
            None => Ok(Self::VerifyOnly),
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyOnly => "verify-only",
            Self::LocalSign => "local-sign",
        }
    }
}

struct LocalScope {
    path: PathBuf,
    password: Zeroizing<String>,
    new_password: Option<Zeroizing<String>>,
    material: Option<jacs_core::material::AgentMaterial>,
}

/// Closed local capability. No path or password is accepted from tool calls.
#[derive(Clone)]
pub struct JacsMcpServer {
    local: Option<Arc<Mutex<LocalScope>>>,
    // One in-flight expensive operation, with no unbounded waiting queue.
    operation: Arc<tokio::sync::Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignArgs {
    document: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyArgs {
    document: String,
    public_key: String,
    algorithm: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportArgs {
    material_json: String,
}

fn arguments<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ErrorData> {
    serde_json::from_value(value)
        .map_err(|_| ErrorData::invalid_params("invalid or unexpected tool parameters", None))
}
fn failure(error: vault::VaultError) -> ErrorData {
    tracing::warn!(
        event = "jacs_local_operation_failed",
        "JACS local operation failed"
    );
    ErrorData::invalid_params(error.to_string(), None)
}
fn document(input: &str) -> Result<Value, ErrorData> {
    if input.len() > MAX_DOCUMENT_BYTES {
        return Err(ErrorData::invalid_params("document exceeds 1 MiB", None));
    }
    jacs_core::strict_json::parse_strict_json(input)
        .map_err(|_| ErrorData::invalid_params("invalid strict JSON document", None))
}
fn public_result(material: &jacs_core::material::AgentMaterial) -> Value {
    json!({"agent":material.agent, "public_key":STANDARD.encode(&material.public_key), "algorithm":material.algorithm})
}

fn read_authorized(local: &LocalScope) -> vault::Result<jacs_core::material::AgentMaterial> {
    let current = vault::read_material(&local.path)?;
    if local.material.as_ref() != Some(&current) {
        return Err(vault::VaultError::Conflict);
    }
    Ok(current)
}

fn committed(result: &vault::Result<()>) -> bool {
    result.is_ok() || matches!(result, Err(vault::VaultError::CommittedNotDurable))
}

impl Default for JacsMcpServer {
    fn default() -> Self {
        Self::verify_only()
    }
}

impl JacsMcpServer {
    pub fn verify_only() -> Self {
        Self {
            local: None,
            operation: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    /// Explicit startup authorization. Existing vaults must unlock immediately;
    /// missing vaults permit only a subsequent create/import at this exact path.
    pub fn local_sign(
        path: PathBuf,
        password: Zeroizing<String>,
        new_password: Option<Zeroizing<String>>,
    ) -> vault::Result<Self> {
        if password.is_empty()
            || password.len() > vault::MAX_PASSWORD_BYTES
            || new_password
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > vault::MAX_PASSWORD_BYTES)
        {
            return Err(vault::VaultError::InvalidPassword);
        }
        let material = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let material = vault::read_material(&path)?;
                vault::unlock(&material, &password)?;
                Some(material)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(vault::VaultError::Io),
        };
        Ok(Self {
            local: Some(Arc::new(Mutex::new(LocalScope {
                path,
                password,
                new_password,
                material,
            }))),
            operation: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    pub fn profile(&self) -> Profile {
        if self.local.is_some() {
            Profile::LocalSign
        } else {
            Profile::VerifyOnly
        }
    }

    pub fn active_tools(&self) -> Vec<Tool> {
        contract::tools()
            .into_iter()
            .filter(|tool| self.local.is_some() || tool.name == "jacs_verify_document")
            .collect()
    }

    /// The same guarded dispatch used by stdio; useful for embedding and tests.
    pub async fn execute(&self, name: &str, args: Value) -> Result<Value, ErrorData> {
        if !self.active_tools().iter().any(|tool| tool.name == name) {
            return Err(ErrorData::invalid_params(
                "tool is unavailable in this profile",
                None,
            ));
        }
        if serde_json::to_vec(&args)
            .map_err(|_| ErrorData::invalid_params("invalid tool arguments", None))?
            .len()
            > MAX_FRAME_BYTES
        {
            return Err(ErrorData::invalid_params(
                "tool arguments exceed the frame limit",
                None,
            ));
        }
        let permit = self.operation.clone().try_acquire_owned().map_err(|_| {
            ErrorData::invalid_params("server is busy; retry after the current operation", None)
        })?;
        let server = self.clone();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            server.execute_blocking(&name, args)
        })
        .await
        .map_err(|_| ErrorData::internal_error("local operation failed", None))?
    }

    fn execute_blocking(&self, name: &str, args: Value) -> Result<Value, ErrorData> {
        if name == "jacs_verify_document" {
            let args: VerifyArgs = arguments(args)?;
            let signed = document(&args.document)?;
            if args.public_key.len() > 16384 {
                return Err(ErrorData::invalid_params(
                    "public key exceeds the limit",
                    None,
                ));
            }
            let key = STANDARD
                .decode(&args.public_key)
                .map_err(|_| ErrorData::invalid_params("invalid base64 public key", None))?;
            let algorithm = SigningAlgorithm::from_wire_str(&args.algorithm)
                .ok_or_else(|| ErrorData::invalid_params("unsupported algorithm", None))?;
            let outcome = CoreAgent::verify_with_key(&signed, &key, algorithm)
                .map_err(|_| ErrorData::invalid_params("document verification failed", None))?;
            if !outcome.valid {
                tracing::warn!(
                    event = "jacs_verification_failed",
                    "JACS signature verification failed"
                );
            }
            return Ok(
                json!({"valid":outcome.valid, "signer_id":outcome.signer_id, "algorithm":algorithm}),
            );
        }
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| ErrorData::invalid_params("local signing is not authorized", None))?;
        let mut local = local
            .lock()
            .map_err(|_| ErrorData::internal_error("local signer unavailable", None))?;
        match name {
            "jacs_create_agent" => {
                let _: Empty = arguments(args)?;
                if local.material.is_some() {
                    return Err(failure(vault::VaultError::AlreadyExists));
                }
                let material = vault::create_material(SigningAlgorithm::Pq2025, &local.password)
                    .map_err(failure)?;
                let persisted = vault::write_material(&local.path, &material);
                if committed(&persisted) {
                    local.material = Some(material.clone());
                }
                persisted.map_err(failure)?;
                Ok(public_result(&material))
            }
            "jacs_import_encrypted_agent" => {
                let args: ImportArgs = arguments(args)?;
                if local.material.is_some() {
                    return Err(failure(vault::VaultError::AlreadyExists));
                }
                let material =
                    vault::parse_material(args.material_json.as_bytes()).map_err(failure)?;
                let agent = vault::unlock(&material, &local.password).map_err(failure)?;
                let material = agent
                    .export_encrypted_material(&local.password)
                    .map_err(|_| failure(vault::VaultError::Crypto))?;
                let persisted = vault::write_material(&local.path, &material);
                if committed(&persisted) {
                    local.material = Some(material.clone());
                }
                persisted.map_err(failure)?;
                Ok(public_result(&material))
            }
            "jacs_sign_document" => {
                let args: SignArgs = arguments(args)?;
                let data = document(&args.document)?;
                let material = read_authorized(&local).map_err(failure)?;
                let signed = vault::unlock(&material, &local.password)
                    .map_err(failure)?
                    .sign_message(&data)
                    .map_err(|_| failure(vault::VaultError::Crypto))?;
                Ok(json!({"document":signed, "algorithm":material.algorithm}))
            }
            "jacs_export_encrypted_agent" => {
                let _: Empty = arguments(args)?;
                let material = read_authorized(&local).map_err(failure)?;
                // A password change or replaced key revokes this process's export authority.
                vault::unlock(&material, &local.password).map_err(failure)?;
                Ok(json!({"material":material}))
            }
            "jacs_rotate_keys" | "jacs_reencrypt_key" => {
                let _: Empty = arguments(args)?;
                let current = read_authorized(&local).map_err(failure)?;
                let next_password = match &local.new_password {
                    Some(password) => &**password,
                    None if name == "jacs_rotate_keys" => &local.password,
                    None => {
                        return Err(ErrorData::invalid_params(
                            "host must supply a new password at startup",
                            None,
                        ));
                    }
                };
                let replacement = if name == "jacs_rotate_keys" {
                    vault::rotate(&current, &local.password, next_password, None)
                } else {
                    vault::reencrypt(&current, &local.password, next_password)
                }
                .map_err(failure)?;
                let persisted = vault::replace_material(&local.path, &current, &replacement);
                if committed(&persisted) {
                    local.material = Some(replacement.clone());
                    if let Some(password) = local.new_password.take() {
                        local.password = password;
                    }
                }
                persisted.map_err(failure)?;
                Ok(public_result(&replacement))
            }
            _ => Err(ErrorData::invalid_params("unknown tool", None)),
        }
    }
}

impl ServerHandler for JacsMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info = Implementation::new("jacs-mcp", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(format!(
            "JACS {}: portable local cryptographic operations. Verification requires an independently trusted public key. Passwords and vault paths are configured by the host, never supplied as tool arguments.",
            self.profile().as_str()
        ));
        info
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.active_tools()))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result = self
            .execute(
                &request.name,
                Value::Object(request.arguments.unwrap_or_default()),
            )
            .await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(result.to_string())]).into())
    }
}

/// Bound each newline-delimited request before rmcp can allocate its line buffer.
/// Strict JSON validation also rejects duplicate properties at the wire boundary.
pub(crate) async fn forward_bounded<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
) -> std::io::Result<()> {
    loop {
        let mut line = Vec::new();
        let count = (&mut input)
            .take(MAX_FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .await?;
        if count == 0 {
            return Ok(());
        }
        if count > MAX_FRAME_BYTES
            || line.last() != Some(&b'\n')
            || jacs_core::strict_json::parse_strict_json_slice(&line).is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid or oversized MCP frame",
            ));
        }
        output.write_all(&line).await?;
    }
}

/// Serve stdio only. Diagnostic output always goes to stderr.
pub async fn serve_stdio(
    server: JacsMcpServer,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let (forward, incoming) = tokio::io::duplex(8192);
    let pump = tokio::spawn(async move {
        if forward_bounded(BufReader::new(tokio::io::stdin()), forward)
            .await
            .is_err()
        {
            tracing::warn!(
                event = "jacs_mcp_input_rejected",
                "MCP input stream rejected"
            );
        }
    });
    let result = async {
        let running = server.serve((incoming, tokio::io::stdout())).await?;
        running.waiting().await?;
        Ok(())
    }
    .await;
    pump.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_wire_rejects_oversized_duplicate_and_incomplete_frames() {
        for input in [
            vec![b'x'; MAX_FRAME_BYTES + 1],
            b"{\"a\":1,\"a\":2}\n".to_vec(),
            b"{}".to_vec(),
        ] {
            let mut output = Vec::new();
            assert!(
                forward_bounded(BufReader::new(input.as_slice()), &mut output)
                    .await
                    .is_err()
            );
            assert!(output.is_empty());
        }
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n";
        let mut output = Vec::new();
        forward_bounded(BufReader::new(input.as_slice()), &mut output)
            .await
            .unwrap();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn busy_call_is_rejected_instead_of_queued() {
        let server = JacsMcpServer::verify_only();
        let _permit = server.operation.try_acquire().unwrap();
        let error = server
            .execute("jacs_verify_document", json!({}))
            .await
            .unwrap_err();
        assert!(error.message.contains("busy"));
    }
}
