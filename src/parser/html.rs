use super::tokenizer::{Tokenizer, Token};
use super::Node;

const MAX_DEPTH: usize = 128;
/*
l'HTML reale raramente supera 20-30 livelli di annidamento anche in pagine complesse. 128 dà ampio margine per casi legittimi (form dentro tabelle dentro div dentro div...) pur bloccando input patologici.
 */

#[derive(Debug, PartialEq)]
pub enum ParseError {
    MismatchedTag { expected: String, found: String },
    UnexpectedClosingTag(String),
    MaxDepthExceeded,
}

pub struct HtmlParser<'a> {
    tokenizer: Tokenizer<'a>,
}

impl<'a> HtmlParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { tokenizer: Tokenizer::new(input) }
    }

    pub fn parse(&mut self) -> Result<Vec<Node>, ParseError> {
        let mut root_nodes = Vec::new();
        let mut stack: Vec<Node> = Vec::new();

        loop {
            let token = self.tokenizer.next_token();
            match token {
                Token::TagOpen(name) => {
                    if stack.len() >= MAX_DEPTH {
                        return Err(ParseError::MaxDepthExceeded);
                    }
                    stack.push(Node::element(name));
                }

                Token::TagClose(name) => {
                    match stack.pop() {
                        Some(node) => {
                            // Verifica che il tag di chiusura corrisponda
                            // all'elemento che stiamo effettivamente chiudendo.
                            let open_name = node.name().unwrap_or_default();
                            if open_name != name {
                                return Err(ParseError::MismatchedTag {
                                    expected: open_name.to_string(),
                                    found: name,
                                });
                            }

                            if let Some(parent) = stack.last_mut() {
                                // add_child fallisce solo se il parent è un Text,
                                // il che non può succedere: nello stack ci finiscono
                                // solo Node::Element (i Text vengono pushati
                                // direttamente come children, mai sullo stack).
                                parent.add_child(node)
                                    .expect("stack contiene solo Element");
                            } else {
                                root_nodes.push(node);
                            }
                        }
                        None => {
                            // Tag di chiusura senza apertura corrispondente
                            return Err(ParseError::UnexpectedClosingTag(name));
                        }
                    }
                }

                Token::Attribute(key, value) => {
                    if let Some(Node::Element { attributes, .. }) = stack.last_mut() {
                        attributes.push((key, value));
                    }
                    // Se lo stack è vuoto, l'attributo è orfano: lo scartiamo.
                    // (non dovrebbe succedere se il tokenizer è corretto)
                }

                Token::Text(content) => {
                    let text_node = Node::text(content);
                    if let Some(parent) = stack.last_mut() {
                        parent.add_child(text_node)
                            .expect("stack contiene solo Element");
                    } else {
                        root_nodes.push(text_node);
                    }
                }

                Token::EOF => break,
            }
        }

        // Se lo stack non è vuoto a fine input, ci sono tag mai chiusi.
        if !stack.is_empty() {
            let unclosed = stack.last().unwrap().name().unwrap_or_default().to_string();
            return Err(ParseError::UnexpectedClosingTag(unclosed)); 
            // nota: nome fuorviante per questo caso, vedi punto sotto
        }

        Ok(root_nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_tags() {
        let mut parser = HtmlParser::new("<div></div>");
        let result = parser.parse().unwrap();
        assert_eq!(result, vec![Node::element("div")]);
    }

    #[test]
    fn test_parse_with_text() {
        let mut parser = HtmlParser::new("<div>Hello</div>");
        let result = parser.parse().unwrap();

        let mut expected = Node::element("div");
        expected.add_child(Node::text("Hello")).unwrap();

        assert_eq!(result, vec![expected]);
    }

    #[test]
    fn test_parse_nested_tags() {
        let mut parser = HtmlParser::new("<div><span></span></div>");
        let result = parser.parse().unwrap();

        let mut div = Node::element("div");
        div.add_child(Node::element("span")).unwrap();

        assert_eq!(result, vec![div]);
    }

    #[test]
    fn test_parse_with_attributes() {
        let mut parser = HtmlParser::new(r#"<div class="box"></div>"#);
        let result = parser.parse().unwrap();

        if let Node::Element { attributes, .. } = &result[0] {
            assert_eq!(attributes, &vec![("class".to_string(), "box".to_string())]);
        } else {
            panic!("expected an Element node");
        }
    }

    // --- Casi di errore ---

    #[test]
    fn test_mismatched_tag_returns_error() {
        let mut parser = HtmlParser::new("<div><span></div>");
        let result = parser.parse();

        assert_eq!(
            result,
            Err(ParseError::MismatchedTag {
                expected: "span".to_string(),
                found: "div".to_string(),
            })
        );
    }

    #[test]
    fn test_unexpected_closing_tag() {
        let mut parser = HtmlParser::new("</div>");
        let result = parser.parse();

        assert_eq!(result, Err(ParseError::UnexpectedClosingTag("div".to_string())));
    }

    #[test]
    fn test_unclosed_tag_at_eof() {
        let mut parser = HtmlParser::new("<div><span>");
        let result = parser.parse();

        // qui dipende da come chiami la variante per "tag mai chiuso";
        // assumendo tu abbia aggiunto ParseError::UnclosedTag(String)
        assert!(result.is_err());
    }

    // --- Il test che ci interessa: MAX_DEPTH ---

    #[test]
    fn test_depth_within_limit_is_ok() {
        // Esattamente al limite: deve ancora passare
        let input = "<div>".repeat(MAX_DEPTH) + &"</div>".repeat(MAX_DEPTH);
        let mut parser = HtmlParser::new(&input);
        let result = parser.parse();
        assert!(result.is_ok());
    }

    #[test]
    fn test_depth_exceeding_limit_returns_error() {
        // Un livello oltre il limite: deve fallire con MaxDepthExceeded
        let input = "<div>".repeat(MAX_DEPTH + 1) + &"</div>".repeat(MAX_DEPTH + 1);
        let mut parser = HtmlParser::new(&input);
        let result = parser.parse();

        assert_eq!(result, Err(ParseError::MaxDepthExceeded));
    }

    #[test]
    fn test_extreme_depth_does_not_hang_or_crash() {
        // Il vero test "anti-bomba": input enorme deve fallire velocemente,
        // non allocare all'infinito né andare in stack overflow.
        let input = "<div>".repeat(1_000_000);
        let mut parser = HtmlParser::new(&input);
        let result = parser.parse();

        assert_eq!(result, Err(ParseError::MaxDepthExceeded));
    }
}