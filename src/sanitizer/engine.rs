use super::SanitizationRule; // Importa il trait definito in mod.rs
use crate::report::report::SanitizationAction;

pub struct SanitizerEngine {
    pub rules: Vec<Box<dyn SanitizationRule>>,
}

impl SanitizerEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Box<dyn SanitizationRule>) {
        self.rules.push(rule);
    }

    pub fn run_all(&self, content: &str) -> Vec<SanitizationAction> {
        self.rules.iter()
            .filter_map(|rule| rule.check(content))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Importa il trait per poterlo usare nel test
    use crate::sanitizer::SanitizationRule; 

    // Creiamo una regola finta per il test
    struct MockRule;
    impl SanitizationRule for MockRule {
        fn name(&self) -> String { "MOCK_RULE".to_string() }
        fn check(&self, content: &str) -> Option<SanitizationAction> {
            if content == "malware" {
                return Some(SanitizationAction {
                    rule_fired: self.name(),
                    location: "test".to_string(),
                    original_fragment: "malware".to_string(),
                    replacement: "safe".to_string(),
                });
            }
            None
        }
    }

    #[test]
    fn test_engine_executes_rules() {
        let mut engine = SanitizerEngine::new();
        engine.add_rule(Box::new(MockRule));

        // Test con input che scatena la regola
        let report = engine.run_all("malware");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].rule_fired, "MOCK_RULE");

        // Test con input pulito
        let report_clean = engine.run_all("hello world");
        assert_eq!(report_clean.len(), 0);
    }
}