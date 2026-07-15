pub mod engine;
pub mod html_rules;
pub mod url_rules;
pub mod resource_rules;
pub mod factory;

use crate::report::report::SanitizationAction;

pub trait SanitizationRule {
    /// Nome identificativo della regola
    fn name(&self) -> String;

    /// Logica che analizza il contenuto e restituisce un'azione se serve pulire
    /// 'content' è il frammento (HTML o URL) da analizzare
    fn check(&self, content: &str) -> Option<SanitizationAction>;
}