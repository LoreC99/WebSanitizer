use crate::parser::Node;
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

    // Il motore accetta il nodo (il DOM)
    pub fn process_node(&self, node: &mut Node, path: &str,report: &mut Vec<SanitizationAction>) {
        // 1. Applica le regole su questo nodo
        for rule in &self.rules {
            if let Some(action) = rule.apply(node, path) {
                report.push(action);
            }
        }
        // 2. Ricorsione: passa ai figli
        if let Node::Element { name, children, .. } = node {
            for (i, child) in children.iter_mut().enumerate() {
                // path tipo "html > body[0] > div[2] > iframe[0]"
                let child_tag = child.name().unwrap_or("#text");
                let child_path = format!("{} > {}[{}]", path, child_tag, i);
                self.process_node(child, &child_path, report);
            }
        }
    }
    //lavora sy node, poi scende ricorsivamente sui figli, e accumula le azioni di sanitizzazione in report
    pub fn run(&self, mut root_nodes: Vec<Node>) -> (Vec<Node>, Vec<SanitizationAction>) {
        let mut report = Vec::new();

        for (i, node) in root_nodes.iter_mut().enumerate() {
            let root_tag = node.name().unwrap_or("#text");
            let root_path = format!("{}[{}]", root_tag, i);
            self.process_node(node, &root_path, &mut report);
        }

        (root_nodes, report)
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