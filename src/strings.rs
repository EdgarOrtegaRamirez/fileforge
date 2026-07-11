//! String extraction from binary files.
//!
//! Extracts printable ASCII and Unicode (UTF-16LE) strings from binary data,
//! similar to the Unix `strings` command but with additional features:
//! configurable minimum length, offset display, JSON output, and filtering.

/// Result of a string extraction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StringMatch {
    /// Byte offset where the string starts.
    pub offset: usize,
    /// The extracted string content.
    pub content: String,
    /// Encoding type ("ascii" or "utf16le").
    pub encoding: &'static str,
    /// Length of the extracted string in characters.
    pub length: usize,
}

/// Extract ASCII printable strings from byte data.
///
/// A "printable" ASCII character is in the range 0x20-0x7E.
/// Strings are sequences of at least `min_length` consecutive printable characters.
pub fn extract_ascii(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let len = i - s;
            if len >= min_length {
                let content = String::from_utf8_lossy(&data[s..i]).to_string();
                results.push(StringMatch {
                    offset: s,
                    content,
                    encoding: "ascii",
                    length: len,
                });
            }
            start = None;
        }
    }

    // Handle string at end of data
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_length {
            let content = String::from_utf8_lossy(&data[s..]).to_string();
            results.push(StringMatch {
                offset: s,
                content,
                encoding: "ascii",
                length: len,
            });
        }
    }

    results
}

/// Extract UTF-16LE strings from byte data.
///
/// A UTF-16LE string consists of pairs of bytes where each pair forms a
/// BMP code point (0x0020-0x007E for printable ASCII in UTF-16LE, or
/// higher values for non-ASCII). For practical purposes, we check for
/// sequences of 16-bit values where the low byte is printable ASCII
/// (0x20-0x7E) and the high byte is 0x00.
pub fn extract_utf16le(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    if data.len() < 2 {
        return results;
    }

    // Align to 2-byte boundary
    for align in 0..2 {
        let mut start: Option<usize> = None;
        let mut i = align;

        while i + 1 < data.len() {
            let low = data[i];
            let high = data[i + 1];

            // Check for printable BMP character in UTF-16LE (U+0020 to U+007E)
            let is_printable = high == 0x00 && (low.is_ascii_graphic() || low == b' ');

            if is_printable {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                let char_len = (i - s) / 2;
                if char_len >= min_length {
                    let mut content = String::with_capacity(char_len);
                    for j in (s..i).step_by(2) {
                        content.push(data[j] as char);
                    }
                    results.push(StringMatch {
                        offset: s,
                        content,
                        encoding: "utf16le",
                        length: char_len,
                    });
                }
                start = None;
            }
            i += 2;
        }

        // Handle string at end
        if let Some(s) = start {
            let remaining = data.len() - s;
            let char_len = remaining / 2;
            if char_len >= min_length {
                let mut content = String::with_capacity(char_len);
                for j in (s..s + char_len * 2).step_by(2) {
                    content.push(data[j] as char);
                }
                results.push(StringMatch {
                    offset: s,
                    content,
                    encoding: "utf16le",
                    length: char_len,
                });
            }
        }
    }

    results
}

/// Extract strings with configurable options.
pub fn extract_strings(data: &[u8], min_length: usize, include_utf16: bool) -> Vec<StringMatch> {
    let mut results = extract_ascii(data, min_length);

    if include_utf16 {
        results.extend(extract_utf16le(data, min_length));
        // Sort by offset to interleave results
        results.sort_by_key(|s| s.offset);
    }

    results
}

/// Format extracted strings for display.
///
/// With `show_offset`, each line is prefixed with the hex offset.
/// Returns a string suitable for printing to stdout.
pub fn format_strings(strings: &[StringMatch], show_offset: bool, max_count: usize) -> String {
    let count = strings.len().min(max_count);
    let truncated = strings.len() > max_count;
    let mut output = String::new();

    for s in &strings[..count] {
        if show_offset {
            let enc = if s.encoding == "utf16le" { "U+" } else { "" };
            output.push_str(&format!("{:08x}  {}{}\n", s.offset, enc, s.content));
        } else {
            output.push_str(&format!("{}\n", s.content));
        }
    }

    if truncated {
        output.push_str(&format!(
            "[-- {} more strings --]\n",
            strings.len() - max_count
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_empty() {
        let results = extract_ascii(b"", 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_ascii_basic() {
        let data = b"hello\x00world\x00test";
        let results = extract_ascii(data, 4);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].content, "hello");
        assert_eq!(results[1].content, "world");
        assert_eq!(results[2].content, "test");
    }

    #[test]
    fn test_extract_ascii_min_length() {
        let data = b"ab\x00abc\x00abcd\x00abcde";
        let results = extract_ascii(data, 4);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "abcd");
        assert_eq!(results[1].content, "abcde");
    }

    #[test]
    fn test_extract_ascii_short_strings_filtered() {
        let data = b"a\x00bb\x00ccc\x00dddd";
        let results = extract_ascii(data, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "dddd");
    }

    #[test]
    fn test_extract_ascii_offsets() {
        let data = b"hello_world";
        let results = extract_ascii(data, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[0].content, "hello_world");
    }

    #[test]
    fn test_extract_ascii_non_printable_boundaries() {
        let data = b"\x00\x01\x02hello\x00\x01\x02world\x00";
        let results = extract_ascii(data, 4);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 3);
        assert_eq!(results[0].content, "hello");
        assert_eq!(results[1].offset, 11);
        assert_eq!(results[1].content, "world");
    }

    #[test]
    fn test_extract_utf16le_basic() {
        // "ABC" in UTF-16LE = b'A', 0x00, b'B', 0x00, b'C', 0x00
        let data = b"A\x00B\x00C\x00";
        let results = extract_utf16le(data, 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "ABC");
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_extract_utf16le_with_padding() {
        // NUL + A\x00B\x00C\x00 + NUL
        let data = b"\x00A\x00B\x00C\x00\x00";
        let results = extract_utf16le(data, 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "ABC");
    }

    #[test]
    fn test_extract_utf16le_empty() {
        let results = extract_utf16le(b"", 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_utf16le_short() {
        let data = b"A\x00";
        let results = extract_utf16le(data, 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_strings_combined() {
        let data = b"hello\x00w\x00o\x00r\x00l\x00d\x00";
        // Has ASCII "hello" at offset 0, and UTF-16LE "world" starting at offset 6
        let results = extract_strings(data, 4, true);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].encoding, "ascii");
        assert_eq!(results[1].encoding, "utf16le");
    }

    #[test]
    fn test_extract_strings_ascii_only() {
        let data = b"hello\x00w\x00o\x00r\x00l\x00d\x00";
        let results = extract_strings(data, 4, false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "hello");
    }

    #[test]
    fn test_format_strings_with_offset() {
        let strings = vec![
            StringMatch {
                offset: 0,
                content: "hello".to_string(),
                encoding: "ascii",
                length: 5,
            },
            StringMatch {
                offset: 10,
                content: "world".to_string(),
                encoding: "ascii",
                length: 5,
            },
        ];
        let formatted = format_strings(&strings, true, 100);
        assert!(formatted.contains("00000000"));
        assert!(formatted.contains("0000000a"));
        assert!(formatted.contains("hello"));
        assert!(formatted.contains("world"));
    }

    #[test]
    fn test_format_strings_truncated() {
        let strings = vec![
            StringMatch {
                offset: 0,
                content: "a".to_string(),
                encoding: "ascii",
                length: 1,
            };
            10
        ];
        let formatted = format_strings(&strings, false, 5);
        assert!(formatted.contains("-- "));
        assert!(formatted.contains("more strings"));
    }

    #[test]
    fn test_format_strings_no_offset() {
        let strings = vec![StringMatch {
            offset: 0,
            content: "hello".to_string(),
            encoding: "ascii",
            length: 5,
        }];
        let formatted = format_strings(&strings, false, 100);
        assert_eq!(formatted.trim(), "hello");
    }

    #[test]
    fn test_string_match_serialization() {
        let s = StringMatch {
            offset: 42,
            content: "test_string".to_string(),
            encoding: "ascii",
            length: 11,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("test_string"));
    }
}
