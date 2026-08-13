pub mod engine;
pub mod html_rules;
pub mod url_rules;
pub mod resource_rules;

use crate::report::report::SanitizationAction;
use crate::parser::Node;
pub use crate::config::loader::HtmlPolicy;



pub trait SanitizationRule {
    /// Nome identificativo della regola
    fn name(&self) -> String;
    fn check(&self, content: &str) -> Option<SanitizationAction>;

    /// Logica che analizza il contenuto e restituisce un'azione se serve pulire
    /// 'content' è il frammento (HTML o URL) da analizzare
    fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction>;
}