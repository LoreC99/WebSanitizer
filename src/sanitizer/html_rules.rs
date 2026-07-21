use super::SanitizationRule;
use super::engine::SanitizerEngine;
use crate::report::report::SanitizationAction;

use crate::parser::Node;
use super::HtmlPolicy;

// =====================================================================
// Regola 1: tag non presente in allowed_tags → rimosso
// =====================================================================

pub struct TagAllowListRule {
    pub config: HtmlPolicy,
}

impl SanitizationRule for TagAllowListRule {
    fn name(&self) -> String { "TAG_NOT_ALLOWLISTED".to_string() }

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
            Node::Text(_) => return None,
        }
    }
}