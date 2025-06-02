# Embedded Documents

JACS supports attaching external files to documents in two ways: **embedded** (contents stored within the document) or **referenced** (metadata stored, contents remain external). This guide explains how to work with both approaches.

## Overview

When attaching files to JACS documents, you can choose between two modes:

- **Embedded (`--embed true`)**: File contents are base64-encoded and stored directly in the document
- **Referenced (`--embed false`)**: Only file metadata and checksums are stored; files remain external

Both approaches provide integrity verification through SHA256 checksums, but differ in storage and portability characteristics.

## How It Works

### File Metadata Structure

Regardless of the embed setting, JACS creates a metadata structure for each attached file:

```json
{
  "mimetype": "image/jpeg",
  "path": "./examples/mobius.jpeg", 
  "embed": true,
  "sha256": "a1b2c3d4e5f6...",
  "contents": "base64-encoded-data..."  // Only present when embed=true
}
```

### Checksum Generation

For **both embedded and referenced files**, JACS:

1. Reads the file contents from disk
2. Calculates a SHA256 hash of the contents
3. Stores this hash in the document metadata
4. Uses this hash for integrity verification during document validation

### Storage Differences

**Embedded Files (`--embed true`)**:
- File contents are base64-encoded and stored in the `contents` field
- Document becomes self-contained and portable
- Larger document file sizes
- No dependency on external files for verification

**Referenced Files (`--embed false`)**:
- Only metadata and checksum are stored
- Original files must remain at their specified paths
- Smaller document file sizes
- External file dependency for verification

## Creating Documents with Attachments

### Basic Attachment (Referenced)

```bash
# Create document with referenced attachment
jacs document create -f document.json --attach ./image.jpg --embed false
```

### Embedded Attachment

```bash
# Create document with embedded attachment
jacs document create -f document.json --attach ./image.jpg --embed true
```

### Multiple Attachments

```bash
# Attach multiple files (directory or comma-separated)
jacs document create -f document.json --attach ./files/ --embed false
```

### Empty Document with Attachments

```bash
# Create document from attachments only
jacs document create --attach ./image.jpg --embed true
```

## Document Verification

During verification, JACS **always validates file integrity** regardless of embed mode:

```bash
jacs document verify -f signed-document.json
```

**For embedded files**: JACS decodes the base64 contents and verifies the checksum.

**For referenced files**: JACS reads the file from the stored path and verifies the checksum.

If any file has been modified since document creation, verification will fail with a "Hash mismatch" error.

## Extracting Embedded Files

You can extract embedded files back to the filesystem:

```bash
# Extract all embedded files from a document
jacs document extract -f document-with-embedded-files.json
```

This command:
1. Reads embedded file contents from the document
2. Decodes the base64 data
3. Writes files back to their original paths
4. Backs up existing files (with timestamp suffix)

## Use Cases

### When to Use Embedded Files

- **Document archival**: Complete self-contained packages
- **Sharing**: Send single file containing all dependencies  
- **Immutable records**: Ensure attachments can't be modified separately
- **Small files**: When storage overhead is acceptable

### When to Use Referenced Files

- **Large files**: Avoid document bloat with large attachments
- **Shared resources**: Multiple documents referencing same files
- **Development**: Working with files that change frequently
- **Storage optimization**: Reduce duplicate storage

## Advanced Features

### Updating Documents with Attachments

```bash
# Update document and add new attachments
jacs document update -f original.json -n modified.json --attach ./new-file.pdf --embed false
```

### Schema Validation with Attachments

```bash
# Create document with custom schema and attachments
jacs document create -f document.json --attach ./data.csv --embed true -s custom-schema.json
```

### File Type Detection

JACS automatically detects MIME types for attached files:
- Images: `image/jpeg`, `image/png`, etc.
- Documents: `application/pdf`, `text/plain`, etc.
- Unknown types: `application/octet-stream`

## Security Considerations

1. **Integrity Protection**: SHA256 checksums detect any file modifications
2. **Signature Coverage**: File metadata is included in document signatures
3. **Path Security**: Be cautious with absolute paths in referenced files
4. **Size Limits**: Consider document size limits when embedding large files

## Troubleshooting

### Common Issues

**"Hash mismatch for file" error**:
- The referenced file has been modified since document creation
- The file path is incorrect or file doesn't exist
- File permissions prevent reading

**"Missing file path" error**:
- Document metadata is corrupted
- Invalid attachment structure

**Large document sizes**:
- Consider using `--embed false` for large files
- Use `extract` command to restore embedded files to filesystem

### Best Practices

1. **Use consistent paths**: Prefer relative paths for portability
2. **Backup strategy**: Keep originals when extracting embedded files
3. **Size management**: Monitor document sizes with embedded content
4. **Path validation**: Verify file paths before creating documents
5. **Regular verification**: Periodically verify document integrity 