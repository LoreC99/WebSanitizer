//NON PIU NECESSARIO IMPLEMENTATO NEI WORKERS
use super::engine::SanitizerEngine;
use super::html_rules::{TagAllowListRule, DangerousAttributeRule, MetaRefreshRule, SsrfAttributeRule, IdnHomographRule};
use crate::config::loader::{default_policy, HtmlPolicy, UrlPolicy};

pub fn create_engine(html_cfg: HtmlPolicy, url_cfg: UrlPolicy) -> SanitizerEngine {
    let mut engine = SanitizerEngine::new();
    
    // 1. Regola Allow-list dei tag
    engine.add_rule(Box::new(TagAllowListRule { config: html_cfg.clone() }));
    
    // 2. Regola Attributi Pericolosi (onclick, javascript:, data:)
    engine.add_rule(Box::new(DangerousAttributeRule { url_config: url_cfg.clone() }));
    
    // 3. Regola Meta-Refresh Redirect
    engine.add_rule(Box::new(MetaRefreshRule { config: html_cfg.clone() }));
    
    // 4. Regola Prevenzione SSRF
    engine.add_rule(Box::new(SsrfAttributeRule { config: url_cfg.clone() }));
    
    // 5. Regola Mitigazione IDN Homograph
    engine.add_rule(Box::new(IdnHomographRule));

    
    
    engine
}

pub fn create_default_engine() -> SanitizerEngine {
    let policy = default_policy();
    create_engine(policy.html, policy.url)
}