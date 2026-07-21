use super::engine::SanitizerEngine;
use super::html_rules::TagAllowListRule;
use crate::config::loader::{default_policy, HtmlPolicy};

pub fn create_engine(html_cfg: HtmlPolicy) -> SanitizerEngine {
    let mut engine = SanitizerEngine::new();
    
    // Registri qui tutte le regole di default con la configurazione HTML fornita
    engine.add_rule(Box::new(TagAllowListRule { config: html_cfg.clone() }));
    //engine.add_rule(Box::new(TrackerBlockRule));
    
    engine
}

pub fn create_default_engine() -> SanitizerEngine {
    let policy = default_policy();
    create_engine(policy.html)
}