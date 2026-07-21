pub use super::SanitizationRule;
use super::engine::SanitizerEngine;
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
    fn name(&self) -> String { "TAG_NOT_ALLOWLISTED".to_string() }

    fn check(&self, content: &str) -> Option<SanitizationAction> {
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