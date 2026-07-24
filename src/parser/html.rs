use scraper::{Html, Node as ScraperNode};
use super::Node; // Importiamo il TUO nodo definito in mod.rs

// Manteniamo il tuo limite per proteggerci dagli attacchi DoS (Resource Bomb)
const MAX_DEPTH: usize = 128;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    MaxDepthExceeded,
    // Abbiamo rimosso MismatchedTag e UnexpectedClosingTag perché
    // scraper (essendo un parser standard HTML5) corregge l'HTML malformato da solo.
}

pub struct HtmlParser<'a> {
    input: &'a str,
}

impl<'a> HtmlParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    pub fn parse(&mut self) -> Result<Vec<Node>, ParseError> {
        // 1. IL CUORE DEL REFACTORING:
        // Usiamo un parser SICURO, ESISTENTE e standard (Mozilla html5ever via scraper)
        // per leggere la stringa. Questo soddisfa in pieno il requisito del PDF.
        let document = Html::parse_fragment(self.input);

        let mut root_nodes = Vec::new();

        // 2. IL WRAPPER:
        // Attraversiamo l'albero sicuro di scraper e lo traduciamo
        // nella tua struttura `Node`, così il tuo SanitizerEngine continua a funzionare intatto.
        for child in document.tree.root().children() {
            if let Some(node) = Self::traverse(child, 1)? {
                root_nodes.push(node);
            }
        }

        Ok(root_nodes)
    }

    // Funzione ricorsiva per la traduzione dell'albero
    fn traverse(node: ego_tree::NodeRef<ScraperNode>, depth: usize) -> Result<Option<Node>, ParseError> {
        // Applichiamo la tua regola di sicurezza sulla profondità massima
        if depth > MAX_DEPTH {
            return Err(ParseError::MaxDepthExceeded);
        }

        match node.value() {
            // Se è un Tag HTML
            ScraperNode::Element(el) => {
                let name = el.name().to_string();
                let mut attributes = Vec::new();

                // Estraiamo gli attributi
                for (key, value) in el.attrs() {
                    attributes.push((key.to_string(), value.to_string()));
                }

                let mut children = Vec::new();

                // Ricorsione sui figli
                for child in node.children() {
                    if let Some(child_node) = Self::traverse(child, depth + 1)? {
                        children.push(child_node);
                    }
                }

                Ok(Some(Node::Element {
                    name,
                    attributes,
                    children,
                }))
            }

            // Se è Testo puro
            ScraperNode::Text(text) => {
                Ok(Some(Node::Text(text.text.to_string())))
            }

            // Ignoriamo Commenti, Doctype e ProcessingInstructions.
            // Eliminarli direttamente dal parser ci protegge preventivamente.
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Funzione helper per trovare un nodo specifico all'interno dell'albero DOM.
    // Ci serve perché scraper avvolge automaticamente i frammenti in <html><body>...</body></html>
    fn find_node<'a>(nodes: &'a [Node], target_name: &str) -> Option<&'a Node> {
        for node in nodes {
            if let Node::Element { name, children, .. } = node {
                if name == target_name {
                    return Some(node);
                }
                if let Some(found) = find_node(children, target_name) {
                    return Some(found);
                }
            }
        }
        None
    }

    #[test]
    fn test_parse_basic_tags() {
        let mut parser = HtmlParser::new("<div></div>");
        let result = parser.parse().unwrap();

        let div = find_node(&result, "div");
        assert!(div.is_some(), "Il nodo <div> dovrebbe essere presente nell'albero");

        if let Some(Node::Element { children, .. }) = div {
            assert!(children.is_empty(), "Il div non dovrebbe avere figli");
        }
    }

    #[test]
    fn test_parse_with_text() {
        let mut parser = HtmlParser::new("<div>Hello</div>");
        let result = parser.parse().unwrap();

        let div = find_node(&result, "div").expect("Div non trovato");
        if let Node::Element { children, .. } = div {
            assert_eq!(children.len(), 1);
            assert_eq!(children[0], Node::Text("Hello".to_string()));
        } else {
            panic!("Mi aspettavo un Node::Element");
        }
    }

    #[test]
    fn test_parse_nested_tags() {
        let mut parser = HtmlParser::new("<div><span></span></div>");
        let result = parser.parse().unwrap();

        let div = find_node(&result, "div").expect("Div non trovato");
        if let Node::Element { children, .. } = div {
            assert_eq!(children.len(), 1);
            if let Node::Element { name, .. } = &children[0] {
                assert_eq!(name, "span");
            } else {
                panic!("Mi aspettavo che il figlio fosse un elemento <span>");
            }
        }
    }

    #[test]
    fn test_parse_with_attributes() {
        let mut parser = HtmlParser::new(r#"<div class="box" id="main"></div>"#);
        let result = parser.parse().unwrap();

        let div = find_node(&result, "div").expect("Div non trovato");
        if let Node::Element { attributes, .. } = div {
            assert!(attributes.contains(&("class".to_string(), "box".to_string())));
            assert!(attributes.contains(&("id".to_string(), "main".to_string())));
        }
    }

    // --- I test di sicurezza e robustezza (Max Depth e Auto-Correzione) ---

    #[test]
    fn test_depth_within_limit_is_ok() {
        // Rientra ampiamente nel limite
        let input = "<div>".repeat(50) + &"</div>".repeat(50);
        let mut parser = HtmlParser::new(&input);
        let result = parser.parse();
        assert!(result.is_ok());
    }

    #[test]
    fn test_depth_exceeding_limit_returns_error() {
        // MAX_DEPTH è 128. Siccome scraper aggiunge implicitamente i livelli <html> e <body>,
        // annidare 128 tag supera il limite di profondità consentito.
        let input = "<div>".repeat(128) + &"</div>".repeat(128);
        let mut parser = HtmlParser::new(&input);
        let result = parser.parse();

        assert_eq!(result, Err(ParseError::MaxDepthExceeded));
    }

    #[test]
    fn test_malformed_html_is_auto_corrected() {
        // In precedenza questo andava in ParseError::MismatchedTag.
        // Ora il parser HTML5 corregge automaticamente i tag sbilanciati chiudendo il <span>.
        let mut parser = HtmlParser::new("<div><span></div>");
        let result = parser.parse().unwrap();

        let span = find_node(&result, "span").expect("Span non trovato");
        assert!(matches!(span, Node::Element { name, .. } if name == "span"));
    }
}