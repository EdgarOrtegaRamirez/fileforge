/// Intelligent hex dump generation.
///
/// Produces formatted hex dumps with ASCII representation, smart grouping,
/// and data type detection for common patterns.
/// Generate a standard hex dump of data.
///
/// Format: `OFFSET: HH HH HH ... | ASCII...`
pub fn hexdump(data: &[u8], bytes_per_line: usize) -> String {
    let mut output = String::new();
    let mut offset = 0;

    for chunk in data.chunks(bytes_per_line) {
        // Offset
        output.push_str(&format!("{:08x}  ", offset));

        // Hex bytes
        for (i, &byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if i == bytes_per_line / 2 - 1 {
                output.push(' ');
            }
        }

        // Padding for incomplete lines
        let padding = bytes_per_line - chunk.len();
        for i in 0..padding {
            output.push_str("   ");
            if i == bytes_per_line / 2 - 1 {
                output.push(' ');
            }
        }

        // ASCII representation
        output.push_str(" |");
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");

        offset += chunk.len();
    }

    output
}

/// Generate a compact hex dump (8 bytes per line, no ASCII).
pub fn hexdump_compact(data: &[u8]) -> String {
    hexdump(data, 8)
}

/// Generate a detailed hex dump with annotations.
///
/// Annotates known patterns like null bytes, printable ASCII, etc.
pub fn hexdump_annotated(data: &[u8]) -> String {
    let mut output = String::new();
    let bytes_per_line = 16;
    let mut offset = 0;

    output.push_str(
        "Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |ASCII              | Type\n",
    );
    output.push_str(
        "--------  -----------------------------------------------  -------------------  ----\n",
    );

    for chunk in data.chunks(bytes_per_line) {
        output.push_str(&format!("{:08x}  ", offset));

        for (i, &byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if i == 7 {
                output.push(' ');
            }
        }

        // Padding
        let padding = bytes_per_line - chunk.len();
        for i in 0..padding {
            output.push_str("   ");
            if i + chunk.len() == 7 {
                output.push(' ');
            }
        }

        // ASCII
        output.push_str(" |");
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');

        // Type annotation
        let line_type = classify_line(chunk);
        if !line_type.is_empty() {
            output.push_str(&format!("  {}", line_type));
        }

        output.push('\n');
        offset += chunk.len();
    }

    output
}

/// Classify a line of bytes by its dominant content type.
fn classify_line(data: &[u8]) -> String {
    if data.iter().all(|&b| b == 0) {
        return "NULL".to_string();
    }
    if data.iter().all(|&b| b == 0xff) {
        return "0xFF".to_string();
    }

    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count();
    let nulls = data.iter().filter(|&&b| b == 0).count();
    let total = data.len();

    if printable as f64 / total as f64 > 0.8 {
        return "TEXT".to_string();
    }
    if nulls as f64 / total as f64 > 0.5 {
        return "NULLS".to_string();
    }
    if data.windows(4).any(|w| w == b"\x00\x00\x00\x00") {
        return "GAPS".to_string();
    }

    String::new()
}

/// Generate a side-by-side comparison hex dump of two byte slices.
pub fn hexdump_compare(data1: &[u8], data2: &[u8]) -> String {
    let mut output = String::new();
    let bytes_per_line = 16;

    output.push_str("File A                                           File B\n");
    output.push_str("Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F    Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F\n");
    output.push_str("--------  -----------------------------------------------  --------  -----------------------------------------------\n");

    let max_len = data1.len().max(data2.len());

    for offset in (0..max_len).step_by(bytes_per_line) {
        // File A
        output.push_str(&format!("{:08x}  ", offset));
        let end_a = (offset + bytes_per_line).min(data1.len());
        if offset < data1.len() {
            let chunk = &data1[offset..end_a];
            for (i, &byte) in chunk.iter().enumerate() {
                output.push_str(&format!("{:02x} ", byte));
                if i == 7 {
                    output.push(' ');
                }
            }
            // Padding
            let padding = bytes_per_line - chunk.len();
            for i in 0..padding {
                output.push_str("   ");
                if i + chunk.len() == 7 {
                    output.push(' ');
                }
            }
        } else {
            output.push_str(&"   ".repeat(bytes_per_line));
            output.push(' ');
        }

        output.push_str("  ");

        // File B
        output.push_str(&format!("{:08x}  ", offset));
        let end_b = (offset + bytes_per_line).min(data2.len());
        if offset < data2.len() {
            let chunk = &data2[offset..end_b];
            for (i, &byte) in chunk.iter().enumerate() {
                output.push_str(&format!("{:02x} ", byte));
                if i == 7 {
                    output.push(' ');
                }
            }
        }

        output.push('\n');
    }

    output
}

/// Create a byte range summary showing regions of different types.
pub fn byte_regions(data: &[u8], window_size: usize) -> Vec<ByteRegion> {
    if data.is_empty() || window_size == 0 {
        return vec![];
    }

    let mut regions = Vec::new();
    let mut current_type = classify_window(&data[..window_size.min(data.len())]);
    let mut start = 0;

    for i in (window_size..data.len()).step_by(window_size) {
        let window = &data[i..(i + window_size).min(data.len())];
        let window_type = classify_window(window);

        if window_type != current_type {
            regions.push(ByteRegion {
                offset: start,
                length: i - start,
                region_type: current_type,
            });
            start = i;
            current_type = window_type;
        }
    }

    // Final region
    regions.push(ByteRegion {
        offset: start,
        length: data.len() - start,
        region_type: current_type,
    });

    regions
}

fn classify_window(data: &[u8]) -> String {
    if data.iter().all(|&b| b == 0) {
        "null".to_string()
    } else if data.iter().all(|&b| b == 0xff) {
        "0xff".to_string()
    } else if data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count() as f64
        / data.len() as f64
        > 0.8
    {
        "text".to_string()
    } else {
        "binary".to_string()
    }
}

/// A region of bytes with a classified type.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ByteRegion {
    pub offset: usize,
    pub length: usize,
    pub region_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump_basic() {
        let data = b"Hello, World!";
        let result = hexdump(data, 16);
        assert!(result.contains("48 65 6c 6c 6f"));
        assert!(result.contains("Hello"));
    }

    #[test]
    fn test_hexdump_empty() {
        let result = hexdump(b"", 16);
        assert!(result.is_empty());
    }

    #[test]
    fn test_hexdump_compact() {
        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07";
        let result = hexdump_compact(data);
        assert!(result.contains("00 01 02 03"));
        assert!(result.contains("04 05 06 07"));
    }

    #[test]
    fn test_hexdump_annotated() {
        let data = b"Hello, World! This is a test.";
        let result = hexdump_annotated(data);
        assert!(result.contains("TEXT"));
    }

    #[test]
    fn test_hexdump_compare() {
        let a = b"Hello";
        let b = b"World";
        let result = hexdump_compare(a, b);
        assert!(result.contains("File A"));
        assert!(result.contains("File B"));
    }

    #[test]
    fn test_byte_regions() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"Hello, World! This is text");
        data.extend_from_slice(&[0xff; 32]);
        let regions = byte_regions(&data, 8);
        assert!(regions.len() >= 2);
    }

    #[test]
    fn test_classify_line() {
        assert_eq!(classify_line(b"\x00\x00\x00\x00"), "NULL");
        assert_eq!(classify_line(b"Hello, World!"), "TEXT");
        assert_eq!(classify_line(b"\xff\xff\xff\xff"), "0xFF");
    }
}
