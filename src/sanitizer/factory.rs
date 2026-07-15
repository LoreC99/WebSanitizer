use super::engine::SanitizerEngine;
//use super::html_rules::ScriptRemovalRule;
//use super::url_rules::TrackerBlockRule;

pub fn create_default_engine() -> SanitizerEngine {
    let mut engine = SanitizerEngine::new();
    
    // Registri qui tutte le regole di default
    //engine.add_rule(Box::new(ScriptRemovalRule));
    //engine.add_rule(Box::new(TrackerBlockRule));
    
    engine
}