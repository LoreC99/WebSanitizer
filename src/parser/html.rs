/* * L'HTML PARSER: Il costruttore del DOM
 * * Questo modulo trasforma la sequenza "piatta" di Token in una struttura gerarchica (Albero DOM).
 * * Logica di sicurezza: 
 * Utilizza uno STACK per gestire l'annidamento e impone un limite (MAX_DEPTH) 
 * per evitare attacchi DoS basati su profondità eccessiva.
 */

/*Esempio Pratico: Input vs. Struttura Node

Immaginiamo di passare questo mini codice al tuo parser:
HTML

<div id="box">Hi</div>

Cosa succede:

    Tokenizer: Produce TagOpen("div"), poi Attribute("id", "box"), poi Text("Hi"), poi TagClose("div").

    Parser: Legge questi token e costruisce l'albero Node.

Cosa ottieni nella struct Node:

Alla fine, la tua funzione parse() ti restituirà un Vec<Node> che contiene questo oggetto:
Rust

Node::Element {
    name: "div".to_string(),
    attributes: vec![("id".to_string(), "box".to_string())],
    children: vec![
        Node::Text("Hi".to_string())
    ],
}
Il Tokenizer (in tokenizer.rs) è un'operazione lineare veloce che "spezzetta" il testo in mattoncini (token).

L'HtmlParser (in html.rs) è il "costruttore" che prende quei token e li organizza gerarchicamente nella struttura ad albero (Node).
*/

/*
1. Il Segreto: Lo Stack (Pila)

Il parser usa uno stack (una lista Vec<Node>) per ricordare "dove si trova" mentre legge il file.

    Pensa allo stack come a una serie di stanze: quando entri in una stanza (tag di apertura), la aggiungi allo stack; quando esci (tag di chiusura), chiudi la porta e torni in quella precedente.

2. Il Flusso di Lavoro (Algoritmo)

Il HtmlParser scorre i token uno ad uno e agisce così:

    Quando arriva un Token::TagOpen(nome):

        Crea un nuovo Node::Element con quel nome.

        Lo "spinge" (push) dentro lo stack.

        Ora il parser sa che tutto ciò che arriverà dopo sarà "figlio" di questo nodo.

    Quando arriva un Token::Text(contenuto):

        Prende l'ultimo nodo aggiunto allo stack e gli "attacca" un Node::Text come figlio.

    Quando arriva un Token::TagClose(nome):

        Il parser "estrae" (pop) l'ultimo nodo dallo stack.

        Se il nome corrisponde (es. </div> chiude <div>), quel nodo è ora "completato".

        Se lo stack non è vuoto, il nodo appena chiuso viene aggiunto come figlio del nodo che ora è diventato l'ultimo nello stack (il suo genitore).

3. Esempio Concreto

Se hai questo HTML: <div><p>Test</p></div>

    Arriva <div: Lo stack diventa [div].

    Arriva <p: Lo stack diventa [div, p].

    Arriva Test: Il nodo Test viene aggiunto come figlio di p (l'ultimo nello stack).

    Arriva </p>: Il nodo p viene rimosso dallo stack. Poiché il div era sotto di lui, il p viene collegato al div.

    Arriva </div>: Il div viene rimosso dallo stack. È finito.

Riassunto visivo della struttura Node

Alla fine, la tua struct Node in mod.rs avrà una forma ricorsiva perfetta:
Rust

Node::Element {
    name: "div".to_string(),
    attributes: vec![], // Campo obbligatorio!
    children: vec![
        Node::Element {
            name: "p".to_string(),
            attributes: vec![], // Campo obbligatorio!
            children: vec![
                Node::Text("Test".to_string())
            ],
        }
    ],
} 
*/
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
                // Quando troviamo un tag aperto, lo mettiamo nello stack
                Token::TagOpen(name) => {
                    if stack.len() >= MAX_DEPTH {
                        return Err(ParseError::MaxDepthExceeded);
                    }
                    stack.push(Node::element(name));
                }

                // Quando chiudiamo, lo togliamo dallo stack e lo attacchiamo al padre
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
                            // Se abbiamo un padre, aggiungiamo questo nodo ai suoi figli
                            if let Some(parent) = stack.last_mut() {
                                // add_child fallisce solo se il parent è un Text,
                                // il che non può succedere: nello stack ci finiscono
                                // solo Node::Element (i Text vengono pushati
                                // direttamente come children, mai sullo stack).
                                parent.add_child(node)
                                    .expect("stack contiene solo Element");
                            } else {
                                // Se stack vuoto, è un nodo radice
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