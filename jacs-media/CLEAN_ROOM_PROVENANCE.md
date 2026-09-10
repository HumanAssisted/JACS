Clean-room Implementation Statement
===================================

The `jacs-media` crate was written from scratch based on publicly published
format specifications:

- PNG 1.2 (W3C, ISO/IEC 15948:2004)
- JPEG File Interchange Format (JFIF) / ISO/IEC 10918-1
- Adobe APP11 metadata segment (Adobe XMP Specification Part 3)
- WebP container specification (Google, 2010; RIFF-based)
- Exif and XMP metadata formats (CIPA DC-008 / ISO 16684-1)

NO code was copied, adapted, or derived from any AGPL-licensed project. The
ST3GG project (https://github.com/elder-plinius/ST3GG, AGPL-3.0) is treated as
untouchable: no one working on `jacs-media` has consulted or will consult
ST3GG's source code while authoring this crate.

The iTXt / APP11 / XMP embedding strategies used here are derived from:
- The PNG 1.2 spec's iTXt chunk definition (Section 11.3).
- Adobe's APP11 JUMBF guidelines (as referenced by the JPEG XT specification).
- The XMP Specification, Part 1 and Part 3 (Adobe, 2012).

All dependencies are Apache-2.0 / MIT compatible (verified at the time of
authoring; `cargo deny check licenses` in CI enforces this). No C/C++ deps.

Licensed under the Apache License, Version 2.0 — see the top-level LICENSE.
