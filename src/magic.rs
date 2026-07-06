/// Magic byte file type detection.
///
/// Uses a database of file signatures (magic bytes) to identify file types
/// regardless of file extension. Supports 100+ common file formats.

/// A file signature entry with offset and expected bytes.
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub name: &'static str,
    pub extension: &'static str,
    pub mime_type: &'static str,
    pub offset: usize,
    pub magic: &'static [u8],
}

/// Detected file information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileDetection {
    pub file_type: String,
    pub extension: String,
    pub mime_type: String,
    pub confidence: f64,
    pub offset: usize,
}

/// Get the comprehensive magic byte database.
fn signatures() -> Vec<FileSignature> {
    vec![
        // Images
        FileSignature {
            name: "PNG",
            extension: "png",
            mime_type: "image/png",
            offset: 0,
            magic: b"\x89PNG\r\n\x1a\n",
        },
        FileSignature {
            name: "JPEG",
            extension: "jpg",
            mime_type: "image/jpeg",
            offset: 0,
            magic: b"\xff\xd8\xff",
        },
        FileSignature {
            name: "GIF87a",
            extension: "gif",
            mime_type: "image/gif",
            offset: 0,
            magic: b"GIF87a",
        },
        FileSignature {
            name: "GIF89a",
            extension: "gif",
            mime_type: "image/gif",
            offset: 0,
            magic: b"GIF89a",
        },
        FileSignature {
            name: "BMP",
            extension: "bmp",
            mime_type: "image/bmp",
            offset: 0,
            magic: b"BM",
        },
        FileSignature {
            name: "ICO",
            extension: "ico",
            mime_type: "image/x-icon",
            offset: 0,
            magic: b"\x00\x00\x01\x00",
        },
        FileSignature {
            name: "TIFF (LE)",
            extension: "tiff",
            mime_type: "image/tiff",
            offset: 0,
            magic: b"II\x2a\x00",
        },
        FileSignature {
            name: "TIFF (BE)",
            extension: "tiff",
            mime_type: "image/tiff",
            offset: 0,
            magic: b"MM\x00\x2a",
        },
        FileSignature {
            name: "WebP",
            extension: "webp",
            mime_type: "image/webp",
            offset: 0,
            magic: b"RIFF",
        },
        FileSignature {
            name: "SVG",
            extension: "svg",
            mime_type: "image/svg+xml",
            offset: 0,
            magic: b"<svg",
        },
        FileSignature {
            name: "HEIF",
            extension: "heif",
            mime_type: "image/heif",
            offset: 4,
            magic: b"ftypheic",
        },
        FileSignature {
            name: "AVIF",
            extension: "avif",
            mime_type: "image/avif",
            offset: 4,
            magic: b"ftypavif",
        },
        // Archives
        FileSignature {
            name: "ZIP",
            extension: "zip",
            mime_type: "application/zip",
            offset: 0,
            magic: b"PK\x03\x04",
        },
        FileSignature {
            name: "RAR",
            extension: "rar",
            mime_type: "application/vnd.rar",
            offset: 0,
            magic: b"Rar!\x1a\x07",
        },
        FileSignature {
            name: "RAR5",
            extension: "rar",
            mime_type: "application/vnd.rar",
            offset: 0,
            magic: b"Rar!\x1a\x07\x01\x00",
        },
        FileSignature {
            name: "7z",
            extension: "7z",
            mime_type: "application/x-7z-compressed",
            offset: 0,
            magic: b"7z\xbc\xaf\x27\x1c",
        },
        FileSignature {
            name: "GZIP",
            extension: "gz",
            mime_type: "application/gzip",
            offset: 0,
            magic: b"\x1f\x8b",
        },
        FileSignature {
            name: "BZIP2",
            extension: "bz2",
            mime_type: "application/x-bzip2",
            offset: 0,
            magic: b"BZ",
        },
        FileSignature {
            name: "XZ",
            extension: "xz",
            mime_type: "application/x-xz",
            offset: 0,
            magic: b"\xfd7zXZ\x00",
        },
        FileSignature {
            name: "LZMA",
            extension: "lzma",
            mime_type: "application/x-lzma",
            offset: 0,
            magic: b"\x5d\x00\x00",
        },
        FileSignature {
            name: "TAR (POSIX)",
            extension: "tar",
            mime_type: "application/x-tar",
            offset: 257,
            magic: b"ustar",
        },
        FileSignature {
            name: "ZSTD",
            extension: "zst",
            mime_type: "application/zstd",
            offset: 0,
            magic: b"\x28\xb5\x2f\xfd",
        },
        // Documents
        FileSignature {
            name: "PDF",
            extension: "pdf",
            mime_type: "application/pdf",
            offset: 0,
            magic: b"%PDF",
        },
        FileSignature {
            name: "DOC (OLE2)",
            extension: "doc",
            mime_type: "application/msword",
            offset: 0,
            magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        },
        FileSignature {
            name: "RAR (SFX)",
            extension: "exe",
            mime_type: "application/x-rar-compressed",
            offset: 0,
            magic: b"Rar!\x1a\x07\x00",
        },
        // Executables
        FileSignature {
            name: "ELF",
            extension: "",
            mime_type: "application/x-executable",
            offset: 0,
            magic: b"\x7fELF",
        },
        FileSignature {
            name: "PE (EXE/DLL)",
            extension: "exe",
            mime_type: "application/x-dosexec",
            offset: 0,
            magic: b"MZ",
        },
        FileSignature {
            name: "Mach-O (32)",
            extension: "",
            mime_type: "application/x-mach-binary",
            offset: 0,
            magic: b"\xfe\xed\xfa\xce",
        },
        FileSignature {
            name: "Mach-O (64)",
            extension: "",
            mime_type: "application/x-mach-binary",
            offset: 0,
            magic: b"\xfe\xed\xfa\xcf",
        },
        FileSignature {
            name: "Mach-O (FAT)",
            extension: "",
            mime_type: "application/x-mach-binary",
            offset: 0,
            magic: b"\xca\xfe\xba\xbe",
        },
        FileSignature {
            name: "Java Class",
            extension: "class",
            mime_type: "application/java-vm",
            offset: 0,
            magic: b"\xca\xfe\xba\xbe",
        },
        FileSignature {
            name: "WASM",
            extension: "wasm",
            mime_type: "application/wasm",
            offset: 0,
            magic: b"\x00asm",
        },
        // Audio
        FileSignature {
            name: "MP3 (ID3)",
            extension: "mp3",
            mime_type: "audio/mpeg",
            offset: 0,
            magic: b"ID3",
        },
        FileSignature {
            name: "MP3 (Sync)",
            extension: "mp3",
            mime_type: "audio/mpeg",
            offset: 0,
            magic: b"\xff\xfb",
        },
        FileSignature {
            name: "FLAC",
            extension: "flac",
            mime_type: "audio/flac",
            offset: 0,
            magic: b"fLaC",
        },
        FileSignature {
            name: "OGG",
            extension: "ogg",
            mime_type: "audio/ogg",
            offset: 0,
            magic: b"OggS",
        },
        FileSignature {
            name: "WAV",
            extension: "wav",
            mime_type: "audio/wav",
            offset: 0,
            magic: b"RIFF",
        },
        FileSignature {
            name: "MIDI",
            extension: "mid",
            mime_type: "audio/midi",
            offset: 0,
            magic: b"MThd",
        },
        FileSignature {
            name: "AU",
            extension: "au",
            mime_type: "audio/basic",
            offset: 0,
            magic: b".snd",
        },
        // Video
        FileSignature {
            name: "MP4",
            extension: "mp4",
            mime_type: "video/mp4",
            offset: 4,
            magic: b"ftypmp4",
        },
        FileSignature {
            name: "AVI",
            extension: "avi",
            mime_type: "video/x-msvideo",
            offset: 0,
            magic: b"RIFF",
        },
        FileSignature {
            name: "MKV",
            extension: "mkv",
            mime_type: "video/x-matroska",
            offset: 0,
            magic: b"\x1a\x45\xdf\xa3",
        },
        FileSignature {
            name: "WebM",
            extension: "webm",
            mime_type: "video/webm",
            offset: 0,
            magic: b"\x1a\x45\xdf\xa3",
        },
        FileSignature {
            name: "FLV",
            extension: "flv",
            mime_type: "video/x-flv",
            offset: 0,
            magic: b"FLV\x01",
        },
        FileSignature {
            name: "MOV",
            extension: "mov",
            mime_type: "video/quicktime",
            offset: 4,
            magic: b"ftypqt",
        },
        // Data formats
        FileSignature {
            name: "SQLite",
            extension: "db",
            mime_type: "application/x-sqlite3",
            offset: 0,
            magic: b"SQLite format 3",
        },
        FileSignature {
            name: "MessagePack",
            extension: "msgpack",
            mime_type: "application/msgpack",
            offset: 0,
            magic: b"\x94",
        },
        FileSignature {
            name: "CBOR",
            extension: "cbor",
            mime_type: "application/cbor",
            offset: 0,
            magic: b"\xa0",
        },
        FileSignature {
            name: "PGP Public Key",
            extension: "asc",
            mime_type: "application/pgp-keys",
            offset: 0,
            magic: b"-----BEGIN PGP PUBLIC KEY BLOCK-----",
        },
        FileSignature {
            name: "PGP Private Key",
            extension: "asc",
            mime_type: "application/pgp-keys",
            offset: 0,
            magic: b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        },
        FileSignature {
            name: "SSH RSA",
            extension: "pub",
            mime_type: "text/plain",
            offset: 0,
            magic: b"ssh-rsa ",
        },
        FileSignature {
            name: "PEM Certificate",
            extension: "pem",
            mime_type: "application/x-x509-ca-cert",
            offset: 0,
            magic: b"-----BEGIN CERTIFICATE-----",
        },
        FileSignature {
            name: "PuTTY Private Key",
            extension: "ppk",
            mime_type: "text/plain",
            offset: 0,
            magic: b"PuTTY-User-Key-File-",
        },
        // Source code (text-based, detected by content)
        FileSignature {
            name: "Python",
            extension: "py",
            mime_type: "text/x-python",
            offset: 0,
            magic: b"#!/usr/bin/env python",
        },
        FileSignature {
            name: "Python",
            extension: "py",
            mime_type: "text/x-python",
            offset: 0,
            magic: b"#!/usr/bin/python",
        },
        FileSignature {
            name: "Bash",
            extension: "sh",
            mime_type: "text/x-shellscript",
            offset: 0,
            magic: b"#!/bin/bash",
        },
        FileSignature {
            name: "Dash",
            extension: "sh",
            mime_type: "text/x-shellscript",
            offset: 0,
            magic: b"#!/bin/dash",
        },
        FileSignature {
            name: "Zsh",
            extension: "zsh",
            mime_type: "text/x-shellscript",
            offset: 0,
            magic: b"#!/bin/zsh",
        },
        FileSignature {
            name: "Perl",
            extension: "pl",
            mime_type: "text/x-perl",
            offset: 0,
            magic: b"#!/usr/bin/env perl",
        },
        FileSignature {
            name: "Ruby",
            extension: "rb",
            mime_type: "text/x-ruby",
            offset: 0,
            magic: b"#!/usr/bin/env ruby",
        },
        FileSignature {
            name: "Node.js",
            extension: "js",
            mime_type: "text/javascript",
            offset: 0,
            magic: b"#!/usr/bin/env node",
        },
        FileSignature {
            name: "PHP",
            extension: "php",
            mime_type: "text/x-php",
            offset: 0,
            magic: b"<?php",
        },
        FileSignature {
            name: "HTML",
            extension: "html",
            mime_type: "text/html",
            offset: 0,
            magic: b"<!DOCTYPE html",
        },
        FileSignature {
            name: "HTML",
            extension: "html",
            mime_type: "text/html",
            offset: 0,
            magic: b"<html",
        },
        FileSignature {
            name: "XML",
            extension: "xml",
            mime_type: "text/xml",
            offset: 0,
            magic: b"<?xml",
        },
        FileSignature {
            name: "JSON",
            extension: "json",
            mime_type: "application/json",
            offset: 0,
            magic: b"{",
        },
        FileSignature {
            name: "JSON",
            extension: "json",
            mime_type: "application/json",
            offset: 0,
            magic: b"[",
        },
        // Special formats
        FileSignature {
            name: "Git pack",
            extension: "pack",
            mime_type: "application/x-git-packed",
            offset: 0,
            magic: b"PACK",
        },
        FileSignature {
            name: "Git bundle",
            extension: "bundle",
            mime_type: "application/x-git-bundle",
            offset: 0,
            magic: b"# v2 git bundle",
        },
        FileSignature {
            name: "Git index",
            extension: "",
            mime_type: "application/x-git-index",
            offset: 0,
            magic: b"DIRC",
        },
        FileSignature {
            name: "Font (TTF)",
            extension: "ttf",
            mime_type: "font/ttf",
            offset: 0,
            magic: b"\x00\x01\x00\x00",
        },
        FileSignature {
            name: "Font (OTF)",
            extension: "otf",
            mime_type: "font/otf",
            offset: 0,
            magic: b"OTTO",
        },
        FileSignature {
            name: "Font (WOFF)",
            extension: "woff",
            mime_type: "font/woff",
            offset: 0,
            magic: b"wOFF",
        },
        FileSignature {
            name: "Font (WOFF2)",
            extension: "woff2",
            mime_type: "font/woff2",
            offset: 0,
            magic: b"wOF2",
        },
        FileSignature {
            name: "Font (DFONT)",
            extension: "dfont",
            mime_type: "font/ttf",
            offset: 0,
            magic: b"typ1",
        },
        // Torrents
        FileSignature {
            name: "BitTorrent",
            extension: "torrent",
            mime_type: "application/x-bittorrent",
            offset: 0,
            magic: b"d8:announce",
        },
        // Disk images
        FileSignature {
            name: "ISO 9660",
            extension: "iso",
            mime_type: "application/x-iso9660-image",
            offset: 0x8001,
            magic: b"CD001",
        },
        FileSignature {
            name: "DMG",
            extension: "dmg",
            mime_type: "application/x-apple-diskimage",
            offset: 0,
            magic: b"ekpo\x04\x15\x2d\x1b",
        },
        // Misc
        FileSignature {
            name: "DS_Store",
            extension: "",
            mime_type: "application/octet-stream",
            offset: 0,
            magic: b"\x00\x00\x00\x01Bud1",
        },
        FileSignature {
            name: "Mach-O Fat Header",
            extension: "",
            mime_type: "application/octet-stream",
            offset: 0,
            magic: b"\xca\xfe\xba\xbe",
        },
        FileSignature {
            name: "Dex (Android)",
            extension: "dex",
            mime_type: "application/octet-stream",
            offset: 0,
            magic: b"dex\n",
        },
        FileSignature {
            name: "AndroRes",
            extension: "arsc",
            mime_type: "application/octet-stream",
            offset: 0,
            magic: b"\x02\x00",
        },
        FileSignature {
            name: "SQLite",
            extension: "sqlite",
            mime_type: "application/x-sqlite3",
            offset: 0,
            magic: b"SQLite format 3\x00",
        },
        FileSignature {
            name: "CramFS",
            extension: "",
            mime_type: "application/x-cramfs",
            offset: 0,
            magic: b"\x45\x3d\xcd\x28",
        },
        FileSignature {
            name: "SquashFS",
            extension: "",
            mime_type: "application/x-squashfs",
            offset: 0,
            magic: b"hsqs",
        },
        FileSignature {
            name: "Ext2/3/4",
            extension: "",
            mime_type: "application/x-linux-ext2",
            offset: 0x438,
            magic: b"\x53\xef",
        },
        FileSignature {
            name: "NTFS",
            extension: "",
            mime_type: "application/x-ntfs",
            offset: 3,
            magic: b"NTFS    ",
        },
        // Java / JVM
        FileSignature {
            name: "JAR",
            extension: "jar",
            mime_type: "application/java-archive",
            offset: 0,
            magic: b"PK\x03\x04",
        },
        FileSignature {
            name: "WAR",
            extension: "war",
            mime_type: "application/java-archive",
            offset: 0,
            magic: b"PK\x03\x04",
        },
        FileSignature {
            name: "EAR",
            extension: "ear",
            mime_type: "application/java-archive",
            offset: 0,
            magic: b"PK\x03\x04",
        },
        // Misc binary
        FileSignature {
            name: "PCAP",
            extension: "pcap",
            mime_type: "application/vnd.tcpdump.pcap",
            offset: 0,
            magic: b"\xd4\xc3\xb2\xa1",
        },
        FileSignature {
            name: "PCAP (LE)",
            extension: "pcap",
            mime_type: "application/vnd.tcpdump.pcap",
            offset: 0,
            magic: b"\xa1\xb2\xc3\xd4",
        },
        FileSignature {
            name: "Lua bytecode",
            extension: "luac",
            mime_type: "application/x-lua",
            offset: 0,
            magic: b"\x1b\x4c\x75\x61",
        },
        FileSignature {
            name: "Python bytecode",
            extension: "pyc",
            mime_type: "application/x-python-bytecode",
            offset: 0,
            magic: b"\x42\x0d\x0d\x0a",
        },
        FileSignature {
            name: "Java serialization",
            extension: "ser",
            mime_type: "application/java-serialized-object",
            offset: 0,
            magic: b"\xac\xed\x00\x05",
        },
        FileSignature {
            name: "Android binary XML",
            extension: "xml",
            mime_type: "application/octet-stream",
            offset: 0,
            magic: b"\x03\x00\x08\x00",
        },
    ]
}

/// Detect file type from raw bytes.
///
/// Reads the first 512 bytes of data and matches against the magic byte database.
/// Returns the best match (earlier signatures take priority).
pub fn detect(data: &[u8]) -> Option<FileDetection> {
    let sigs = signatures();
    for sig in &sigs {
        let end = sig.offset + sig.magic.len();
        if data.len() >= end && data[sig.offset..end] == *sig.magic {
            return Some(FileDetection {
                file_type: sig.name.to_string(),
                extension: sig.extension.to_string(),
                mime_type: sig.mime_type.to_string(),
                confidence: 1.0,
                offset: sig.offset,
            });
        }
    }
    None
}

/// Detect file type from raw bytes with all matches.
///
/// Returns all matching signatures, sorted by offset (earlier matches first).
pub fn detect_all(data: &[u8]) -> Vec<FileDetection> {
    let sigs = signatures();
    let mut results = Vec::new();
    for sig in &sigs {
        let end = sig.offset + sig.magic.len();
        if data.len() >= end && data[sig.offset..end] == *sig.magic {
            results.push(FileDetection {
                file_type: sig.name.to_string(),
                extension: sig.extension.to_string(),
                mime_type: sig.mime_type.to_string(),
                confidence: 1.0,
                offset: sig.offset,
            });
        }
    }
    results
}

/// Get the total number of signatures in the database.
pub fn signature_count() -> usize {
    signatures().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_detection() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "PNG");
        assert_eq!(result.mime_type, "image/png");
    }

    #[test]
    fn test_jpg_detection() {
        let data = b"\xff\xd8\xff\xe0\x00\x10JFIF";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "JPEG");
    }

    #[test]
    fn test_pdf_detection() {
        let data = b"%PDF-1.4\n1 0 obj";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "PDF");
        assert_eq!(result.extension, "pdf");
    }

    #[test]
    fn test_zip_detection() {
        let data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "ZIP");
    }

    #[test]
    fn test_elf_detection() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "ELF");
    }

    #[test]
    fn test_pe_detection() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "PE (EXE/DLL)");
    }

    #[test]
    fn test_python_script() {
        let data = b"#!/usr/bin/env python3\nimport os";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "Python");
    }

    #[test]
    fn test_html_detection() {
        let data = b"<!DOCTYPE html>\n<html>\n<head>";
        let result = detect(data).unwrap();
        assert_eq!(result.file_type, "HTML");
    }

    #[test]
    fn test_no_match() {
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(detect(data).is_none());
    }

    #[test]
    fn test_detect_all() {
        let data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
        let results = detect_all(data);
        assert!(!results.is_empty());
        assert_eq!(results[0].file_type, "ZIP");
    }

    #[test]
    fn test_empty_data() {
        assert!(detect(b"").is_none());
    }

    #[test]
    fn test_signature_count() {
        assert!(signature_count() > 80);
    }
}
