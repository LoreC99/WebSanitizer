use std::net::IpAddr;
use url::Url;
pub use super::SanitizationRule;
use crate::report::report::SanitizationAction;

use crate::parser::Node;

use crate::config::loader::HtmlPolicy;
use crate::config::loader::UrlPolicy;

// =====================================================================
// Regola 1: tag non presente in allowed_tags → rimosso
// =====================================================================

pub struct TagAllowListRule {
    pub config: HtmlPolicy,
}


impl SanitizationRule for TagAllowListRule {
    fn name(&self) -> String { "TAG_NOT_ALLOW_LISTED".to_string() }

    fn check(&self, _content: &str) -> Option<SanitizationAction> {
        todo!()
    }

    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
        /*
        Se node è un Node::Element, estrae name (riferimento mutabile al nome del tag) 
        e children (riferimento mutabile ai figli), e continua l'esecuzione.
        Se node è un Node::Text (cioè non è un elemento, è testo puro), il pattern non combacia, 
        ed esegue il blocco else { return None } — cioè: "un nodo di testo non ha un tag, 
        quindi questa regola non lo riguarda, esci subito".
        */
        match node {
            Node::Element { name, children, .. } => { 
                //t.eq_ignore_ascii_case(name) confronta ignorando maiuscole/minuscole
                let allowed = self.config.allowed_tags.iter().any(|t| t.eq_ignore_ascii_case(name));
                if allowed { return None; }

                let fragment = format!("<{}>...{} children...</{}>", name, children.len(), name);
                /*
                *node = ... dereferenzia e sovrascrive quello che sta in quella posizione di memoria. 
                Non stiamo creando un nuovo nodo separato: stiamo sostituendo sul posto l'Element con 
                un Text("") vuoto, mantenendo la posizione esatta nell'albero
                */
                *node = Node::text("");
                Some(SanitizationAction {
                    rule_fired: self.name(),
                    location: path.to_string(),
                    original_fragment: fragment,
                    replacement: "".into(),
                })
                
            }
            Node::Text(_) => None,
        }
    }
}

// =====================================================================
// Regola 2: Rimozione Attributi Pericolosi (Inline Handlers, javascript:, data:)
// =====================================================================

pub struct DangerousAttributeRule {
    // Aggiungiamo la configurazione URL per leggere i flag del TOML
    pub url_config: UrlPolicy, // Sostituisci "super::UrlPolicy" con il tipo corretto della tua config URL
}

impl SanitizationRule for DangerousAttributeRule {
    fn name(&self) -> String { "DANGEROUS_ATTRIBUTE_REMOVED".to_string() }

    fn check(&self, _content: &str) -> Option<SanitizationAction> { None }

    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
        if let Node::Element { name, attributes, .. } = node {
            let mut removed_attrs = Vec::new();
            let mut safe_attributes = Vec::new();

            for (key, value) in attributes.drain(..) {
                let key_lower = key.to_lowercase();
                // Usiamo trim() per rimuovere eventuali spazi bianchi all'inizio della stringa
                // che un attaccante potrebbe usare per eludere il controllo (es: " javascript:alert()")
                let value_lower = value.trim().to_lowercase();

                let mut is_dangerous = false;

                // 1. Controllo Inline Handlers (Sempre rimossi, prescinde dal TOML)
                if key_lower.starts_with("on") {
                    is_dangerous = true;
                }

                // 2. Controllo Pseudo-protocollo "javascript:"
                if self.url_config.block_javascript_uris {
                    let targets = ["href", "src", "action", "formaction"];
                    if targets.contains(&key_lower.as_str()) && value_lower.starts_with("javascript:") {
                        is_dangerous = true;
                    }
                }

                // 3. Controllo Pseudo-protocollo "data:"
                if self.url_config.block_data_uris {
                    let targets = ["href", "src", "data", "object"];
                    if targets.contains(&key_lower.as_str()) && value_lower.starts_with("data:") {
                        is_dangerous = true;
                    }
                }

                // Smistamento finale
                if is_dangerous {
                    removed_attrs.push(format!("{}=\"{}\"", key, value));
                } else {
                    safe_attributes.push((key, value));
                }
            }

            // Riapplichiamo al nodo solo gli attributi che hanno superato i controlli
            *attributes = safe_attributes;

            // Generiamo il report se abbiamo fatto "pulizia"
            if !removed_attrs.is_empty() {
                return Some(SanitizationAction {
                    rule_fired: self.name(),
                    location: format!("{}[{}]", path, name),
                    original_fragment: format!("Attributi malevoli: {}", removed_attrs.join(", ")),
                    replacement: "Rimossi".to_string(),
                });
            }
        }

        None
    }
}

// =====================================================================
// Regola 3: Blocco dei Meta-Refresh Redirect
// =====================================================================

pub struct MetaRefreshRule {
    // La regola riceve la configurazione HTML in cui hai aggiunto block_meta_refresh
    pub config: HtmlPolicy,
}

impl SanitizationRule for MetaRefreshRule {
    fn name(&self) -> String { "META_REFRESH_REMOVED".to_string() }

    fn check(&self, _content: &str) -> Option<SanitizationAction> { None }

    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
        // Se nel TOML l'opzione è falsa o mancante, disabilitiamo il controllo
        if !self.config.block_meta_refresh {
            return None;
        }

        if let Node::Element { name, attributes, .. } = node {
            // Controlliamo se è un tag <meta> (ignorando maiuscole/minuscole)
            if name.eq_ignore_ascii_case("meta") {
                let mut is_malicious_refresh = false;

                // Verifichiamo la presenza di http-equiv="refresh"
                for (key, value) in attributes.iter() {
                    if key.eq_ignore_ascii_case("http-equiv") && value.trim().eq_ignore_ascii_case("refresh") {
                        is_malicious_refresh = true;
                        break;
                    }
                }

                if is_malicious_refresh {
                    // Creiamo una copia degli attributi per il report originale
                    let original_attrs: Vec<String> = attributes
                        .iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, v))
                        .collect();

                    // Neutralizziamo il nodo svuotando tutti i suoi attributi
                    attributes.clear();

                    return Some(SanitizationAction {
                        rule_fired: self.name(),
                        location: format!("{}[{}]", path, name),
                        original_fragment: format!("<meta {}>", original_attrs.join(" ")),
                        replacement: "<meta> (Neutralizzato)".to_string(),
                    });
                }
            }
        }

        None
    }
}

// =====================================================================
// Regola 4: Prevenzione SSRF negli attributi HTML
// =====================================================================

pub struct SsrfAttributeRule {
    // Puoi passare una configurazione se vuoi permettere un toggle on/off
    pub config: UrlPolicy,
}

impl SsrfAttributeRule {
    /// Funzione helper per verificare se un host è un IP interno, privato o loopback
    fn is_internal_or_private(host: &str) -> bool {
        // Blocco diretto di localhost
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }

        // Tenta il parsing come indirizzo IP
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    // 127.0.0.0/8 (Loopback)
                    if octets[0] == 127 { return true; }
                    // 169.254.0.0/16 (Link-local / Cloud Metadata)
                    if octets[0] == 169 && octets[1] == 254 { return true; }
                    // 10.0.0.0/8 (Private RFC 1918)
                    if octets[0] == 10 { return true; }
                    // 172.16.0.0/12 (Private RFC 1918)
                    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
                    // 192.168.0.0/16 (Private RFC 1918)
                    if octets[0] == 192 && octets[1] == 168 { return true; }
                }
                IpAddr::V6(ipv6) => {
                    // ::1 (Loopback IPv6)
                    if ipv6.is_loopback() { return true; }
                    // Indirizzi locali unici (fc00::/7)
                    if ipv6.segments()[0] & 0xfe00 == 0xfc00 { return true; }
                }
            }
        }

        false
    }
}

impl SanitizationRule for SsrfAttributeRule {
    fn name(&self) -> String { "SSRF_REFERENCE_REMOVED".to_string() }

    fn check(&self, _content: &str) -> Option<SanitizationAction> { None }

    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
        if let Node::Element { name, attributes, .. } = node {
            let mut removed_attrs = Vec::new();
            let mut safe_attributes = Vec::new();

            // Attributi che comunemente scatenano richieste di rete
            let target_attrs = ["src", "href", "action", "data", "ping"];

            for (key, value) in attributes.drain(..) {
                let key_lower = key.to_lowercase();
                let mut is_dangerous = false;

                if target_attrs.contains(&key_lower.as_str()) {
                    let trimmed_val = value.trim();

                    // 1. Blocco immediato evasioni sui parser (Host/Split Confusion)
                    // Il backslash e il punto codificato (%2e) sono classici vettori
                    // per confondere i parser e far risolvere host malevoli.
                    if trimmed_val.contains('\\') || trimmed_val.to_lowercase().contains("%2e") {
                        is_dangerous = true;
                    }

                    // 2. Analisi approfondita della struttura dell'URL
                    // Normalizziamo temporaneamente la stringa per garantire che il
                    // parser Rust non si interrompa o faccia errori di interpretazione.
                    let normalized_for_parsing = trimmed_val.replace('\\', "/");

                    if let Ok(parsed_url) = Url::parse(&normalized_for_parsing) {

                        // A. Blocco Userinfo Confusion (es. http://trusted.com@evil.com)
                        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
                            is_dangerous = true;
                        }

                        // B. Blocco risoluzione verso IP interni/loopback (già presente e ottimo)
                        if let Some(host_str) = parsed_url.host_str() {
                            if Self::is_internal_or_private(host_str) {
                                is_dangerous = true;
                            }
                        }
                    }
                }

                if is_dangerous {
                    removed_attrs.push(format!("{}=\"{}\"", key, value));
                } else {
                    safe_attributes.push((key, value));
                }
            }

            *attributes = safe_attributes;

            if !removed_attrs.is_empty() {
                return Some(SanitizationAction {
                    rule_fired: self.name(),
                    location: format!("{}[{}]", path, name),
                    // Modificato il messaggio per evidenziare il blocco della Host Confusion
                    original_fragment: format!("SSRF/Host Confusion bloccato: {}", removed_attrs.join(", ")),
                    replacement: "Rimossi".to_string(),
                });
            }
        }

        None
    }
}

// =====================================================================
// Regola 5: Mitigazione IDN Homograph / Unicode Spoofing
// =====================================================================

pub struct IdnHomographRule;

impl SanitizationRule for IdnHomographRule {
    fn name(&self) -> String { "IDN_HOMOGRAPH_MITIGATED".to_string() }

    fn check(&self, _content: &str) -> Option<SanitizationAction> { None }

    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
        if let Node::Element { name, attributes, .. } = node {
            let mut actions_taken = Vec::new();
            let mut safe_attributes = Vec::new();

            // Attributi che possono contenere URL navigabili o risorse
            let target_attrs = ["href", "src", "action", "formaction"];

            for (key, value) in attributes.drain(..) {
                let key_lower = key.to_lowercase();
                let trimmed_value = value.trim();

                // Se l'attributo è un target e contiene caratteri NON-ASCII (Unicode)
                if target_attrs.contains(&key_lower.as_str()) && !trimmed_value.is_ascii() {

                    match Url::parse(trimmed_value) {
                        Ok(parsed_url) => {
                            // Il parser converte automaticamente l'host Unicode in Punycode (ASCII)
                            let punycode_url = parsed_url.to_string();

                            safe_attributes.push((key.clone(), punycode_url));
                            actions_taken.push(format!("{} (convertito in Punycode)", key));
                        }
                        Err(_) => {
                            // Se contiene Unicode ma non è un URL valido, lo scartiamo del tutto
                            actions_taken.push(format!("{} (rimosso, URL invalido)", key));
                        }
                    }
                } else {
                    // Se è già ASCII puro o non è un attributo a rischio, lo manteniamo inalterato
                    safe_attributes.push((key, value));
                }
            }

            *attributes = safe_attributes;

            if !actions_taken.is_empty() {
                return Some(SanitizationAction {
                    rule_fired: self.name(),
                    location: format!("{}[{}]", path, name),
                    original_fragment: format!("Rilevato Unicode/IDN in: {}", actions_taken.join(", ")),
                    replacement: "Normalizzato in ASCII".to_string(),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Importa il trait per poterlo usare nel test
    use crate::sanitizer::SanitizationRule; 
    use crate::parser::Node;
    

    #[test]
    fn test_html_rules_tagallowed_executes_rules() {
        let config = HtmlPolicy {
            allow_scripts: true,
            remove_iframes: false,
            block_meta_refresh: false,
            allowed_tags: vec!["div".to_string(), "p".to_string()],
        };
        let rule = TagAllowListRule { config };

        // Test con input che scatena la regola
        let mut node = Node::element("script");
        let report = rule.apply(&mut node, "html > body[0] > script[0]");
        assert!(report.is_some());
        assert_eq!(report.unwrap().rule_fired, "TAG_NOT_ALLOW_LISTED");

        // Test con input pulito
        let mut clean_node = Node::element("div");
        let report_clean = rule.apply(&mut clean_node, "html > body[0] > div[0]");

        assert!(report_clean.is_none());
        
    }

    #[test]
    fn test_html_rules_meta_refresh_executes_rules() {
        let config = HtmlPolicy {
            allow_scripts: true,
            remove_iframes: false,
            block_meta_refresh: true,
            allowed_tags: vec!["div".to_string(), "p".to_string()],
        };
        let rule = MetaRefreshRule { config };

        // Test con input che scatena la regola, dangerous attributes: meta http-equiv="refresh" 
        let mut vett = Vec::new();
        vett.push(("http-equiv".to_string(), "refresh".to_string()));
        vett.push(("content".to_string(), "5; url=http://evil.com".to_string()));

        let mut node = Node::element("meta");
        if let Node::Element { attributes, .. } = &mut node {
            *attributes = vett;
        }
        let report = rule.apply(&mut node, "html > body[0] > meta[0]");
        assert!(report.is_some());
        assert_eq!(report.unwrap().rule_fired, "META_REFRESH_REMOVED");

        // Test con input pulito
        let mut safe = Vec::new();
        safe.push(("charset".to_string(), "utf-8".to_string()));

        let mut clean_node = Node::element("meta");
        if let Node::Element { attributes, .. } = &mut clean_node {
            *attributes = safe;
        }

        let report_clean = rule.apply(&mut clean_node, "html > body[0] > meta[1]");
        assert!(report_clean.is_none());
        
    }

    #[test]
    fn test_dangerous_attribute_rule_removes_inline_handlers() {
        let url_config = UrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            block_data_uris: true,
            block_javascript_uris: true,
            blocklist_path: None,
        };
        let rule = DangerousAttributeRule { url_config };

        let mut attributes = vec![
            ("onclick".to_string(), "alert('xss')".to_string()),
            ("class".to_string(), "btn-primary".to_string()),
        ];
        let mut node = Node::element("button");
        if let Node::Element { attributes: ref mut attrs, .. } = node {
            *attrs = attributes;
        }

        let report = rule.apply(&mut node, "html > body[0] > button[0]");
        assert!(report.is_some());
        let report_val = report.unwrap();
        assert_eq!(report_val.rule_fired, "DANGEROUS_ATTRIBUTE_REMOVED");

        if let Node::Element { attributes: ref remaining_attrs, .. } = node {
            assert_eq!(remaining_attrs.len(), 1);
            assert_eq!(remaining_attrs[0].0, "class");
        } else {
            panic!("Expected Node::Element");
        }
    }

    #[test]
    fn test_dangerous_attribute_rule_removes_javascript_and_data_uris() {
        let url_config = UrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            block_data_uris: true,
            block_javascript_uris: true,
            blocklist_path: None,
        };
        let rule = DangerousAttributeRule { url_config };

        let attributes = vec![
            ("href".to_string(), "javascript:alert(1)".to_string()),
            ("src".to_string(), "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==".to_string()),
            ("id".to_string(), "safe_link".to_string()),
        ];
        let mut node = Node::element("a");
        if let Node::Element { attributes: ref mut attrs, .. } = node {
            *attrs = attributes;
        }

        let report = rule.apply(&mut node, "html > body[0] > a[0]");
        assert!(report.is_some());

        if let Node::Element { attributes: ref remaining_attrs, .. } = node {
            assert_eq!(remaining_attrs.len(), 1);
            assert_eq!(remaining_attrs[0].0, "id");
        } else {
            panic!("Expected Node::Element");
        }
    }

    #[test]
    fn test_iframe_removed_when_tag_not_allowed() {
        let config = HtmlPolicy {
            allow_scripts: false,
            remove_iframes: true,
            block_meta_refresh: true,
            allowed_tags: vec!["div".to_string(), "p".to_string()], // 'iframe' NON presente
        };
        let rule = TagAllowListRule { config };

        let mut node = Node::element("iframe");
        let report = rule.apply(&mut node, "html > body[0] > iframe[0]");
        assert!(report.is_some());
        assert_eq!(report.unwrap().rule_fired, "TAG_NOT_ALLOW_LISTED");

        if let Node::Text(content) = node {
            assert_eq!(content, "");
        } else {
            panic!("Node should be replaced with empty text");
        }
    }
}