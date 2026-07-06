/// Character encoding detection.
///
/// Detects encoding using BOM (Byte Order Mark) detection, statistical
/// analysis, and heuristic patterns. Supports UTF-8, UTF-16 (LE/BE),
/// UTF-32 (LE/BE), ASCII, and Latin-1.

/// Detected encoding information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EncodingDetection {
    /// Detected encoding name.
    pub encoding: String,
    /// BOM detected (if any).
    pub bom: Option<String>,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// Is the data valid UTF-8?
    pub valid_utf8: bool,
    /// Is the data pure ASCII (bytes 0-127 only)?
    pub pure_ascii: bool,
    /// Percentage of null bytes (indicator of UTF-16/32).
    pub null_percentage: f64,
}

/// Detect the character encoding of data.
pub fn detect_encoding(data: &[u8]) -> EncodingDetection {
    if data.is_empty() {
        return EncodingDetection {
            encoding: "unknown".to_string(),
            bom: None,
            confidence: 0.0,
            valid_utf8: false,
            pure_ascii: false,
            null_percentage: 0.0,
        };
    }

    // Check BOM first
    let (encoding, bom, confidence) = if data.starts_with(b"\xef\xbb\xbf") {
        (
            "UTF-8 (BOM)".to_string(),
            Some("UTF-8 BOM (EF BB BF)".to_string()),
            1.0,
        )
    } else if data.starts_with(b"\xff\xfe\x00\x00") {
        (
            "UTF-32 (LE)".to_string(),
            Some("UTF-32 LE BOM (FF FE 00 00)".to_string()),
            1.0,
        )
    } else if data.starts_with(b"\x00\x00\xfe\xff") {
        (
            "UTF-32 (BE)".to_string(),
            Some("UTF-32 BE BOM (00 00 FE FF)".to_string()),
            1.0,
        )
    } else if data.starts_with(b"\xff\xfe") {
        (
            "UTF-16 (LE)".to_string(),
            Some("UTF-16 LE BOM (FF FE)".to_string()),
            1.0,
        )
    } else if data.starts_with(b"\xfe\xff") {
        (
            "UTF-16 (BE)".to_string(),
            Some("UTF-16 BE BOM (FE FF)".to_string()),
            1.0,
        )
    } else {
        // No BOM — use heuristics
        detect_encoding_heuristic(data)
    };

    let valid_utf8 = is_valid_utf8(data);
    let pure_ascii = data.iter().all(|&b| b < 0x80);
    let null_count = data.iter().filter(|&&b| b == 0).count();
    let null_percentage = null_count as f64 / data.len() as f64;

    EncodingDetection {
        encoding,
        bom,
        confidence,
        valid_utf8,
        pure_ascii,
        null_percentage,
    }
}

fn detect_encoding_heuristic(data: &[u8]) -> (String, Option<String>, f64) {
    let null_count = data.iter().filter(|&&b| b == 0).count();
    let null_ratio = null_count as f64 / data.len() as f64;

    // High null ratio suggests UTF-16 or UTF-32
    if null_ratio > 0.3 {
        // Check if nulls are at even or odd positions
        let even_nulls = data.iter().step_by(2).filter(|&&b| b == 0).count();
        let odd_nulls = data.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();

        if even_nulls > odd_nulls * 3 {
            // Nulls mostly at even positions → UTF-16 LE or UTF-32 LE
            if null_ratio > 0.45 {
                ("UTF-32 (LE, no BOM)".to_string(), None, 0.7)
            } else {
                ("UTF-16 (LE, no BOM)".to_string(), None, 0.7)
            }
        } else if odd_nulls > even_nulls * 3 {
            // Nulls mostly at odd positions → UTF-16 BE or UTF-32 BE
            if null_ratio > 0.45 {
                ("UTF-32 (BE, no BOM)".to_string(), None, 0.7)
            } else {
                ("UTF-16 (BE, no BOM)".to_string(), None, 0.7)
            }
        } else {
            // Mixed nulls — likely binary
            ("Binary".to_string(), None, 0.5)
        }
    } else if is_valid_utf8(data) {
        // Check if it's pure ASCII
        if data.iter().all(|&b| b < 0x80) {
            ("ASCII".to_string(), None, 1.0)
        } else {
            // Has high bytes and is valid UTF-8
            ("UTF-8".to_string(), None, 0.95)
        }
    } else {
        // Not valid UTF-8 and low nulls — likely Latin-1/ISO-8859-1
        ("Latin-1 (ISO-8859-1)".to_string(), None, 0.6)
    }
}

/// Check if data is valid UTF-8.
pub fn is_valid_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let result = detect_encoding(b"");
        assert_eq!(result.encoding, "unknown");
    }

    #[test]
    fn test_ascii() {
        let result = detect_encoding(b"Hello, World!");
        assert_eq!(result.encoding, "ASCII");
        assert!(result.pure_ascii);
        assert!(result.valid_utf8);
    }

    #[test]
    fn test_utf8_bom() {
        let data = b"\xef\xbb\xbfHello";
        let result = detect_encoding(data);
        assert!(result.encoding.contains("UTF-8"));
        assert!(result.bom.is_some());
    }

    #[test]
    fn test_utf16_le_bom() {
        let data = b"\xff\xfeH\x00e\x00l\x00l\x00o\x00";
        let result = detect_encoding(data);
        assert!(result.encoding.contains("UTF-16"));
        assert!(result.bom.is_some());
    }

    #[test]
    fn test_utf16_be_bom() {
        let data = b"\xfe\xff\x00H\x00e\x00l\x00l\x00o";
        let result = detect_encoding(data);
        assert!(result.encoding.contains("UTF-16"));
    }

    #[test]
    fn test_utf8_multibyte() {
        let data = "こんにちは世界".as_bytes();
        let result = detect_encoding(data);
        assert!(result.valid_utf8);
        assert!(!result.pure_ascii);
    }

    #[test]
    fn test_is_valid_utf8() {
        assert!(is_valid_utf8(b"Hello"));
        assert!(is_valid_utf8("日本語".as_bytes()));
        assert!(!is_valid_utf8(&[0xff, 0xfe]));
    }
}
