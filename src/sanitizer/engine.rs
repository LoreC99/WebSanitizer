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
        if let Node::Element { name: _, children, .. } = node {
            for (i, child) in children.iter_mut().enumerate() {
                // path tipo "html > body[0] > div[2] > iframe[0]"
                let child_tag = child.name().unwrap_or("#text");
                let child_path = format!("{} > {}[{}]", path, child_tag, i);
                self.process_node(child, &child_path, report);
            }
        }
    }
    //lavora su node, poi scende ricorsivamente sui figli, e accumula le azioni di sanitizzazione in report
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
    // Assicurati di importare il Node (se non è già importato globalmente nel file)
    use crate::parser::Node;
    use crate::sanitizer::SanitizationRule;

    // 1. Creiamo una regola finta per il test
    struct MockRule;

    impl SanitizationRule for MockRule {
        fn name(&self) -> String { "MOCK_RULE".to_string() }

        fn check(&self, _content: &str) -> Option<SanitizationAction> {
            todo!()
        }

        // Sostituiamo il todo!() con una vera logica di ispezione dei Nodi
        fn apply(&self, node: &mut Node, path: &str) -> Option<SanitizationAction> {
            // Controlliamo se il nodo corrente è un elemento HTML e si chiama "malware"
            if let Node::Element { name, .. } = node {
                if name == "malware" {
                    return Some(SanitizationAction {
                        rule_fired: self.name(),
                        location: path.to_string(), // Registriamo il path dove è scattato
                        original_fragment: "<malware>".to_string(),
                        replacement: "Rimosso".to_string(),
                    });
                }
            }
            None
        }
    }

    #[test]
    fn test_engine_executes_rules_and_catches_threats() {
        let mut engine = SanitizerEngine::new();
        engine.add_rule(Box::new(MockRule));

        // 2. Creiamo un DOM fittizio INFETTO
        // Rappresenta questo HTML: <div><malware></malware></div>
        let mut root_node = Node::element("div");
        root_node.add_child(Node::element("malware")).expect("Impossibile aggiungere figlio");

        let malware_dom = vec![root_node];

        // 3. Eseguiamo il motore con la funzione run()
        let (_processed_dom, report) = engine.run(malware_dom);

        // 4. Verifichiamo che la regola sia scattata correttamente
        assert_eq!(report.len(), 1, "Il motore doveva rilevare 1 minaccia");
        assert_eq!(report[0].rule_fired, "MOCK_RULE");
        // Il path generato dalla tua ricorsione dovrebbe essere qualcosa tipo "div[0] > malware[0]"
        assert!(report[0].location.contains("malware"));
    }

    #[test]
    fn test_engine_ignores_clean_dom() {
        let mut engine = SanitizerEngine::new();
        engine.add_rule(Box::new(MockRule));

        // 2. Creiamo un DOM fittizio PULITO
        // Rappresenta questo HTML: <div><p></p></div>
        let mut root_node = Node::element("div");
        root_node.add_child(Node::element("p")).expect("Impossibile aggiungere figlio");

        let clean_dom = vec![root_node];

        // 3. Eseguiamo il motore
        let (_processed_dom, report) = engine.run(clean_dom);

        // 4. Verifichiamo che il report sia vuoto
        assert_eq!(report.len(), 0, "Il motore non doveva rilevare nulla su un DOM pulito");
    }
}