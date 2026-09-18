//! MIME type detection based on file extension.
//!
//! This module provides simple, predictable MIME type detection
//! using file extensions rather than magic bytes.

/// Determines the MIME type for a file based on its extension.
///
/// Returns `"application/octet-stream"` for unknown extensions.
///
/// # Examples
///
/// ```
/// use jacs::mime::mime_from_extension;
///
/// assert_eq!(mime_from_extension("document.pdf"), "application/pdf");
/// assert_eq!(mime_from_extension("image.png"), "image/png");
/// assert_eq!(mime_from_extension("unknown.xyz"), "application/octet-stream");
/// ```
pub fn mime_from_extension(path: &str) -> &'static str {
    match path.rsplit('.').next().map(|s| s.to_lowercase()).as_deref() {
        // Documents
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("md") | Some("markdown") => "text/markdown",
        Some("html") | Some("htm") => "text/html",
        Some("xml") => "application/xml",
        Some("csv") => "text/csv",
        Some("yaml") | Some("yml") => "application/x-yaml",
        Some("toml") => "application/toml",

        // Images
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("bmp") => "image/bmp",
        Some("tiff") | Some("tif") => "image/tiff",

        // Audio
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("flac") => "audio/flac",
        Some("aac") => "audio/aac",
        Some("m4a") => "audio/mp4",

        // Video
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("avi") => "video/x-msvideo",
        Some("mov") => "video/quicktime",
        Some("mkv") => "video/x-matroska",

        // Archives
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") | Some("gzip") => "application/gzip",
        Some("bz2") => "application/x-bzip2",
        Some("xz") => "application/x-xz",
        Some("7z") => "application/x-7z-compressed",
        Some("rar") => "application/vnd.rar",

        // Code
        Some("js") => "application/javascript",
        Some("ts") => "application/typescript",
        Some("py") => "text/x-python",
        Some("rs") => "text/x-rust",
        Some("go") => "text/x-go",
        Some("java") => "text/x-java",
        Some("c") | Some("h") => "text/x-c",
        Some("cpp") | Some("hpp") | Some("cc") => "text/x-c++",
        Some("css") => "text/css",
        Some("sh") => "application/x-sh",

        // Binary/unknown
        _ => "application/octet-stream",
    }
}

/// Returns the file extension for a given MIME type.
///
/// This is the inverse of `mime_from_extension`, useful when
/// extracting embedded files.
///
/// # Examples
///
/// ```
/// use jacs::mime::extension_from_mime;
///
/// assert_eq!(extension_from_mime("application/pdf"), Some("pdf"));
/// assert_eq!(extension_from_mime("image/png"), Some("png"));
/// ```
pub fn extension_from_mime(mime_type: &str) -> Option<&'static str> {
    match mime_type {
        // Documents
        "application/pdf" => Some("pdf"),
        "application/json" => Some("json"),
        "text/plain" => Some("txt"),
        "text/markdown" => Some("md"),
        "text/html" => Some("html"),
        "application/xml" | "text/xml" => Some("xml"),
        "text/csv" => Some("csv"),
        "application/x-yaml" => Some("yaml"),
        "application/toml" => Some("toml"),

        // Images
        "image/jpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/svg+xml" => Some("svg"),
        "image/x-icon" => Some("ico"),
        "image/bmp" => Some("bmp"),
        "image/tiff" => Some("tiff"),

        // Audio
        "audio/mpeg" => Some("mp3"),
        "audio/wav" => Some("wav"),
        "audio/ogg" => Some("ogg"),
        "audio/flac" => Some("flac"),
        "audio/aac" => Some("aac"),
        "audio/mp4" => Some("m4a"),

        // Video
        "video/mp4" => Some("mp4"),
        "video/webm" => Some("webm"),
        "video/x-msvideo" => Some("avi"),
        "video/quicktime" => Some("mov"),
        "video/x-matroska" => Some("mkv"),

        // Archives
        "application/zip" => Some("zip"),
        "application/x-tar" => Some("tar"),
        "application/gzip" => Some("gz"),
        "application/x-bzip2" => Some("bz2"),
        "application/x-xz" => Some("xz"),
        "application/x-7z-compressed" => Some("7z"),
        "application/vnd.rar" => Some("rar"),

        // Code
        "application/javascript" => Some("js"),
        "application/typescript" => Some("ts"),
        "text/x-python" => Some("py"),
        "text/x-rust" => Some("rs"),
        "text/x-go" => Some("go"),
        "text/x-java" => Some("java"),
        "text/x-c" => Some("c"),
        "text/x-c++" => Some("cpp"),
        "text/css" => Some("css"),
        "application/x-sh" => Some("sh"),

        // Unknown
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_extensions() {
        assert_eq!(mime_from_extension("document.pdf"), "application/pdf");
        assert_eq!(mime_from_extension("data.json"), "application/json");
        assert_eq!(mime_from_extension("readme.txt"), "text/plain");
        assert_eq!(mime_from_extension("page.html"), "text/html");
    }

    #[test]
    fn test_image_extensions() {
        assert_eq!(mime_from_extension("photo.jpg"), "image/jpeg");
        assert_eq!(mime_from_extension("photo.jpeg"), "image/jpeg");
        assert_eq!(mime_from_extension("icon.png"), "image/png");
        assert_eq!(mime_from_extension("animation.gif"), "image/gif");
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(mime_from_extension("FILE.PDF"), "application/pdf");
        assert_eq!(mime_from_extension("IMAGE.PNG"), "image/png");
        assert_eq!(mime_from_extension("data.JSON"), "application/json");
    }

    #[test]
    fn test_unknown_extension() {
        assert_eq!(mime_from_extension("file.xyz"), "application/octet-stream");
        assert_eq!(
            mime_from_extension("noextension"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_extension_from_mime() {
        assert_eq!(extension_from_mime("application/pdf"), Some("pdf"));
        assert_eq!(extension_from_mime("image/png"), Some("png"));
        assert_eq!(extension_from_mime("unknown/type"), None);
    }
}
