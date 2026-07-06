# Security Policy

## Overview
FileForge is a **read-only** binary analysis tool. It does not:
- Make network calls
- Write files to disk
- Execute external programs
- Store any data persistently

## Input Validation
- All file paths are validated before access
- File sizes are checked before processing
- Buffer sizes are bounded to prevent memory exhaustion
- Error messages do not leak sensitive information

## Path Traversal
- File paths are normalized and checked for `..` sequences
- Symlink targets are resolved and validated
- No path concatenation without proper normalization

## Memory Safety
- Written in Rust — memory safe by design
- No `unsafe` code blocks
- Proper error handling (no `unwrap()` on user input)
- Graceful degradation on malformed input

## Dependencies
- Minimal dependencies (clap, serde, chrono, csv)
- All dependencies are well-maintained and widely used
- No transitive dependencies with known vulnerabilities (as of last audit)

## Reporting Vulnerabilities
If you discover a security vulnerability in FileForge, please open a GitHub issue with the "security" label. Do not disclose the vulnerability publicly until a fix is available.

## Best Practices
- Run FileForge from untrusted directories with appropriate OS-level permissions
- Verify binary integrity before analysis
- Use `--json` output for scripting to avoid shell injection
- Be cautious when analyzing files from untrusted sources — malformed input could trigger unexpected behavior in the parser
