from __future__ import annotations

import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "homebrew_release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release-homebrew.yml"


def load_homebrew_release():
    spec = importlib.util.spec_from_file_location("homebrew_release", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shell_run_blocks(text: str) -> list[str]:
    """Extract scalar ``run`` values without adding a YAML test dependency."""

    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        if not stripped.startswith("run:"):
            index += 1
            continue
        indent = len(line) - len(stripped)
        value = stripped.removeprefix("run:").strip()
        if value not in {"|", ">", "|-", ">-", "|+", ">+"}:
            blocks.append(value)
            index += 1
            continue
        index += 1
        body: list[str] = []
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            body.append(candidate)
            index += 1
        blocks.append("\n".join(body))
    return blocks


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        url: str,
        *,
        content_length: int | None = None,
        status: int = 200,
    ) -> None:
        self._body = io.BytesIO(body)
        self._url = url
        self.status = status
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class HomebrewReleaseValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = load_homebrew_release()

    def test_versions_use_strict_shared_semver_validation(self) -> None:
        self.assertEqual(self.release.validate_version("0.11.4"), "0.11.4")
        self.assertEqual(
            self.release.validate_version("1.2.3-rc.1+build.7"),
            "1.2.3-rc.1+build.7",
        )
        for value in (
            "01.2.3",
            "1.2",
            "1.2.3\nname=owned",
            "1.2.3$(touch OWNED)",
            "1.2.3`touch OWNED`",
            "-1.2.3",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.release.validate_version(value)

    def test_validates_pypi_package_tap_repository_and_branch(self) -> None:
        self.assertEqual(self.release.validate_pypi_package("hai-sdk.core"), "hai-sdk.core")
        self.assertEqual(
            self.release.validate_tap_repository("HumanAssisted/homebrew-jacs"),
            "HumanAssisted/homebrew-jacs",
        )
        self.assertEqual(self.release.validate_tap_branch("release/stable"), "release/stable")

        invalid_packages = (
            "-haisdk",
            "haisdk/../../owned",
            "haisdk%2fowned",
            "haisdk\nowned=true",
            "haisdk?x=1",
        )
        invalid_repositories = (
            "--upload-pack=owned",
            "owner/repo/extra",
            "owner/../repo",
            "/owner/repo",
            "owner/repo.git\nowned=true",
        )
        invalid_branches = (
            "--force",
            "../main",
            "refs/heads/main:owned",
            "main\nowned=true",
            "main.lock",
            "main@{1}",
            "/main",
        )
        for value in invalid_packages:
            with self.subTest(kind="package", value=value), self.assertRaises(ValueError):
                self.release.validate_pypi_package(value)
        for value in invalid_repositories:
            with self.subTest(kind="repository", value=value), self.assertRaises(ValueError):
                self.release.validate_tap_repository(value)
        for value in invalid_branches:
            with self.subTest(kind="branch", value=value), self.assertRaises(ValueError):
                self.release.validate_tap_branch(value)

    def test_outputs_are_whitelisted_and_single_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            values = {
                "jacs_version": "0.11.4",
                "jacs_sha256": "a" * 64,
                "haisdk_version": "0.4.1",
                "haisdk_sdist_url": "https://files.pythonhosted.org/packages/a/haisdk-0.4.1.tar.gz",
                "haisdk_sha256": "b" * 64,
                "haisdk_pypi_package": "haisdk",
                "tap_repository": "HumanAssisted/homebrew-jacs",
                "tap_branch": "master",
            }
            self.release.write_outputs(output, values)
            self.assertEqual(
                set(line.split("=", 1)[0] for line in output.read_text().splitlines()),
                set(values),
            )

            with self.assertRaises(ValueError):
                self.release.write_outputs(output, {**values, "tap_branch": "main\nowned=true"})
            with self.assertRaises(ValueError):
                self.release.write_outputs(output, {**values, "extra": "value"})
            with self.assertRaises(ValueError):
                self.release.write_outputs(
                    output,
                    {
                        **values,
                        "haisdk_sdist_url": (
                            "https://files.pythonhosted.org/packages/a/"
                            "another-package-0.4.1.tar.gz"
                        ),
                    },
                )


class HomebrewReleaseFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = load_homebrew_release()

    def test_bounded_fetch_retries_timeout_and_passes_timeout_to_opener(self) -> None:
        url = "https://pypi.org/pypi/haisdk/json"
        attempts: list[tuple[str, int]] = []

        def opener(request, *, timeout: int):
            attempts.append((request.full_url, timeout))
            if len(attempts) < 3:
                raise TimeoutError("slow endpoint")
            return FakeResponse(b"{}", url)

        body = self.release.fetch_bytes(
            url,
            allowed_origins={"https://pypi.org"},
            max_bytes=32,
            attempts=3,
            timeout_seconds=7,
            delay_seconds=0,
            opener=opener,
            sleep=lambda _seconds: None,
        )
        self.assertEqual(body, b"{}")
        self.assertEqual(attempts, [(url, 7), (url, 7), (url, 7)])

    def test_bounded_fetch_stops_after_timeout_attempt_limit(self) -> None:
        url = "https://pypi.org/pypi/haisdk/json"
        attempts = 0

        def opener(_request, *, timeout: int):
            nonlocal attempts
            attempts += 1
            self.assertEqual(timeout, 2)
            raise TimeoutError("still slow")

        with self.assertRaisesRegex(RuntimeError, "after 2 attempts"):
            self.release.fetch_bytes(
                url,
                allowed_origins={"https://pypi.org"},
                max_bytes=32,
                attempts=2,
                timeout_seconds=2,
                delay_seconds=0,
                opener=opener,
            )
        self.assertEqual(attempts, 2)

    def test_bounded_fetch_rejects_oversize_declared_or_streamed_body(self) -> None:
        url = (
            "https://static.crates.io/crates/jacs-cli/"
            "jacs-cli-0.11.4.crate"
        )
        for response in (
            FakeResponse(b"small", url, content_length=33),
            FakeResponse(b"x" * 33, url),
        ):
            with self.subTest(headers=response.headers), self.assertRaisesRegex(
                ValueError, "size limit"
            ):
                self.release.fetch_bytes(
                    url,
                    allowed_origins={"https://static.crates.io"},
                    max_bytes=32,
                    attempts=1,
                    timeout_seconds=1,
                    delay_seconds=0,
                    opener=lambda _request, **_kwargs: response,
                )

        with self.assertRaisesRegex(ValueError, "Content-Length"):
            self.release.fetch_bytes(
                url,
                allowed_origins={"https://static.crates.io"},
                max_bytes=32,
                attempts=1,
                timeout_seconds=1,
                delay_seconds=0,
                opener=lambda _request, **_kwargs: FakeResponse(
                    b"short", url, content_length=10
                ),
            )

    def test_bounded_fetch_rejects_hostile_origin_and_redirect(self) -> None:
        safe_url = "https://pypi.org/pypi/haisdk/json"
        hostile_url = "https://attacker.example/steal"
        with self.assertRaisesRegex(ValueError, "origin"):
            self.release.fetch_bytes(
                hostile_url,
                allowed_origins={"https://pypi.org"},
                max_bytes=32,
                attempts=1,
                timeout_seconds=1,
                delay_seconds=0,
            )
        with self.assertRaisesRegex(ValueError, "redirect"):
            self.release.fetch_bytes(
                safe_url,
                allowed_origins={"https://pypi.org"},
                max_bytes=32,
                attempts=1,
                timeout_seconds=1,
                delay_seconds=0,
                opener=lambda _request, **_kwargs: FakeResponse(b"{}", hostile_url),
            )

    def test_resolve_uses_exact_fixed_urls_and_verifies_sdist_digest(self) -> None:
        version = "0.11.4"
        package = "haisdk"
        sdk_version = "0.4.1"
        crate = b"crate archive"
        sdist = b"sdk sdist"
        sdist_digest = hashlib.sha256(sdist).hexdigest()
        sdist_url = (
            "https://files.pythonhosted.org/packages/ab/cd/"
            "haisdk-0.4.1.tar.gz"
        )
        metadata = (
            "{"
            '"info":{"name":"haisdk","version":"0.4.1"},'
            '"releases":{"0.4.1":[{'
            '"packagetype":"sdist",'
            '"filename":"haisdk-0.4.1.tar.gz",'
            f'"url":"{sdist_url}",'
            f'"digests":{{"sha256":"{sdist_digest}"}}'
            "}]}"
            "}"
        ).encode()
        expected_urls = {
            "https://pypi.org/pypi/haisdk/json": metadata,
            (
                "https://static.crates.io/crates/jacs-cli/"
                "jacs-cli-0.11.4.crate"
            ): crate,
            sdist_url: sdist,
        }
        requested: list[tuple[str, frozenset[str], int]] = []

        def fetch(url: str, *, allowed_origins: set[str], max_bytes: int, **_kwargs):
            requested.append((url, frozenset(allowed_origins), max_bytes))
            return expected_urls[url]

        result = self.release.resolve_release(
            jacs_version_input=version,
            haisdk_version_input=sdk_version,
            haisdk_package_input=package,
            tap_repository_input="HumanAssisted/homebrew-jacs",
            tap_branch_input="master",
            github_ref="refs/heads/main",
            manifest_path=ROOT / "jacs" / "Cargo.toml",
            fetch=fetch,
        )
        self.assertEqual(result["jacs_sha256"], hashlib.sha256(crate).hexdigest())
        self.assertEqual(result["haisdk_sha256"], sdist_digest)
        self.assertEqual(result["haisdk_sdist_url"], sdist_url)
        self.assertEqual(
            [url for url, _origins, _limit in requested],
            list(expected_urls),
        )
        self.assertEqual(
            requested[0][1], frozenset({"https://pypi.org"})
        )
        self.assertEqual(
            requested[1][1], frozenset({"https://static.crates.io"})
        )
        self.assertEqual(
            requested[2][1], frozenset({"https://files.pythonhosted.org"})
        )

    def test_rejects_hostile_sdist_url_digest_and_placeholder(self) -> None:
        base = {
            "packagetype": "sdist",
            "filename": "haisdk-0.4.1.tar.gz",
            "url": "https://files.pythonhosted.org/packages/a/haisdk-0.4.1.tar.gz",
            "digests": {"sha256": "a" * 64},
        }
        mutations = (
            {"url": "https://attacker.example/haisdk-0.4.1.tar.gz"},
            {"url": "https://files.pythonhosted.org@attacker.example/haisdk-0.4.1.tar.gz"},
            {"url": " https://files.pythonhosted.org/packages/a/haisdk-0.4.1.tar.gz"},
            {"url": "https://files.pythonhosted.org/packages/a/../haisdk-0.4.1.tar.gz"},
            {"url": "https://files.pythonhosted.org/packages/a/__JACS_VERSION__.tar.gz"},
            {
                "filename": 'haisdk-0.4.1";system("id").tar.gz',
                "url": (
                    "https://files.pythonhosted.org/packages/a/"
                    'haisdk-0.4.1%22%3Bsystem%28%22id%22%29.tar.gz'
                ),
            },
            {"digests": {"sha256": "not-a-digest"}},
        )
        for mutation in mutations:
            item = {**base, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.release.validate_sdist(item)

    def test_sdist_digest_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "digest"):
            self.release.verify_sha256(b"different bytes", "a" * 64, "HAISDK sdist")


class HomebrewReleaseRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = load_homebrew_release()

    def test_renders_without_leaving_placeholders(self) -> None:
        text = 'url "__URL__"\nsha256 "__SHA__"\n'
        rendered = self.release.render_template(
            text,
            {"__URL__": "https://example.test/archive", "__SHA__": "a" * 64},
        )
        self.assertEqual(
            rendered,
            f'url "https://example.test/archive"\nsha256 "{"a" * 64}"\n',
        )

    def test_rejects_missing_unknown_and_placeholder_replacements(self) -> None:
        cases = (
            ("only __URL__", {"__URL__": "safe", "__SHA__": "a" * 64}),
            ("__URL__ __UNKNOWN__", {"__URL__": "safe"}),
            ("__URL__", {"__URL__": "__OWNED__"}),
        )
        for template, replacements in cases:
            with self.subTest(template=template), self.assertRaises(ValueError):
                self.release.render_template(template, replacements)

    def test_render_formulas_writes_both_outputs_only_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jacs_template = root / "jacs.tmpl"
            haisdk_template = root / "haisdk.tmpl"
            output = root / "generated" / "Formula"
            jacs_template.write_text("__JACS_VERSION__ __JACS_SHA256__\n")
            haisdk_template.write_text("__HAISDK_SDIST_URL__ __HAISDK_SHA256__\n")
            values = {
                "jacs_version": "0.11.4",
                "jacs_sha256": "a" * 64,
                "haisdk_sdist_url": "https://files.pythonhosted.org/packages/a/haisdk-0.4.1.tar.gz",
                "haisdk_sha256": "b" * 64,
            }
            self.release.render_formulas(
                values,
                jacs_template=jacs_template,
                haisdk_template=haisdk_template,
                output_directory=output,
            )
            self.assertNotIn("__", (output / "jacs.rb").read_text())
            self.assertNotIn("__", (output / "haisdk.rb").read_text())

            jacs_template.write_text("__JACS_VERSION__ __UNKNOWN__\n")
            with self.assertRaises(ValueError):
                self.release.render_formulas(
                    values,
                    jacs_template=jacs_template,
                    haisdk_template=haisdk_template,
                    output_directory=output,
                )

    def test_jacs_formula_installs_the_supported_cli_crate(self) -> None:
        template = (
            ROOT / ".github" / "homebrew-templates" / "jacs.rb.tmpl"
        ).read_text()
        self.assertIn(
            "https://static.crates.io/crates/jacs-cli/"
            "jacs-cli-__JACS_VERSION__.crate",
            template,
        )
        self.assertNotIn("/crates/jacs/", template)
        self.assertNotIn('"--features", "cli"', template)
        rendered = self.release.render_template(
            template,
            {
                "__JACS_VERSION__": "0.11.4",
                "__JACS_SHA256__": "a" * 64,
            },
        )
        self.assertIn("jacs-cli-0.11.4.crate", rendered)


class HomebrewReleaseWorkflowTests(unittest.TestCase):
    def test_workflow_uses_helpers_and_never_interpolates_inputs_in_shell(self) -> None:
        text = WORKFLOW.read_text()
        self.assertIn("python3 scripts/homebrew_release.py resolve", text)
        self.assertIn("python3 scripts/homebrew_release.py render", text)
        self.assertNotIn("sed \\", text)
        for run in shell_run_blocks(text):
            self.assertNotRegex(run, r"\$\{\{\s*github\.event\.inputs\.")
            self.assertNotRegex(run, r"\$\{\{\s*inputs\.")
            self.assertNotRegex(run, r"\$\{\{\s*steps\.resolve\.outputs\.")

    def test_workflow_passes_validated_values_through_env_and_action_inputs(self) -> None:
        text = WORKFLOW.read_text()
        self.assertIn("repository: ${{ steps.resolve.outputs.tap_repository }}", text)
        self.assertIn("ref: ${{ steps.resolve.outputs.tap_branch }}", text)
        self.assertIn("TAP_BRANCH: ${{ steps.resolve.outputs.tap_branch }}", text)
        self.assertIn("TAP_REPOSITORY: ${{ steps.resolve.outputs.tap_repository }}", text)
        self.assertIn('GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0', text)
        self.assertIn(
            'git push "https://github.com/${TAP_REPOSITORY}.git" "HEAD:${TAP_BRANCH}"',
            text,
        )
        self.assertNotIn("git push origin", text)
        self.assertNotIn("https://x-access-token:", text)
        self.assertIn('jacs v${JACS_VERSION}, haisdk v${HAISDK_VERSION}', text)
        self.assertIn("timeout-minutes: 10", text)


if __name__ == "__main__":
    unittest.main()
