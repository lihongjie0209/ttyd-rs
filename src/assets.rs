/// Embedded, gzip-compressed index.html bytes.
/// Generated in build.rs and included from OUT_DIR/index.html.gz
///
/// At runtime we either:
///   - send the raw gzip bytes (if client sends Accept-Encoding: gzip)
///   - decompress and send raw HTML
pub static INDEX_HTML_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html.gz"));

/// Decompress the embedded HTML and return it as a Vec<u8>.
pub fn decompress_html() -> Vec<u8> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(INDEX_HTML_GZ);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .expect("failed to decompress embedded HTML");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_html_decompresses() {
        let html = decompress_html();
        assert!(!html.is_empty());
        let s = String::from_utf8_lossy(&html);
        assert!(s.contains("<!doctype html") || s.contains("<html"));
    }
}
