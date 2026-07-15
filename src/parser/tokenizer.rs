
/*perché hai separato tokenizer da html (che conterrà il DOM Builder):

Tokenizer: È un'operazione lineare. Legge il file una volta sola, senza memoria. È veloce e perfetto per gestire i limiti di buffer (DoS).

HTML (DOM Builder): È un'operazione gerarchica. Gestisce l'annidamento (<div><span></span></div>). È qui che applicherai la logica di profondità massima per evitare le "bombe ricorsive". */
use std::collections::VecDeque;

#[derive(Debug, PartialEq)]
pub enum Token {
    TagOpen(String),           // <div
    TagClose(String),          // </div>
    Attribute(String, String), // href="valore"
    Text(String),              // contenuto testuale
    EOF,                       // Fine del file
}

pub struct Tokenizer<'a> {
    input: &'a str,
    pos: usize, // indice a BYTE, sempre coerente con &str slicing
    // Coda di token già "pronti" ma non ancora restituiti:
    // serve perché un singolo tag può generare più token
    // (TagOpen + N Attribute) in un'unica scansione.
    pending: VecDeque<Token>,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            pending: VecDeque::new(),
        }
    }

    // Restituisce il prossimo char senza avanzare, senza usare nth()
    // (che sarebbe O(n) e comunque basato su indici a char, non a byte)
    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    // Avanza di UN carattere (non di un byte!), rispettando UTF-8
    fn advance(&mut self) {
        if let Some(ch) = self.peek() {
            self.pos += ch.len_utf8();
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.advance();
        }
    }

    // Legge caratteri finché non incontra `stop`, senza consumarlo
    fn read_until(&mut self, stop: char) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == stop {
                break;
            }
            self.advance();
        }
        self.input[start..self.pos].to_string()
    }

    // Legge il nome di un tag: si ferma a spazio, '>', '/' (self-closing)
    fn read_until_space_or_bracket(&mut self) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() || ch == '>' || ch == '/' {
                break;
            }
            self.advance();
        }
        self.input[start..self.pos].to_string()
    }

    // Legge un attributo tipo: class="container"
    // Precondizione: pos è posizionato sulla prima lettera della chiave
    fn read_attribute(&mut self) -> Option<Token> {
        let key = self.read_until('=');
        if key.trim().is_empty() {
            return None;
        }
        self.advance(); // salta '='

        if self.peek() == Some('"') {
            self.advance(); // salta la virgoletta di apertura
        }
        let value = self.read_until('"');
        if self.peek() == Some('"') {
            self.advance(); // salta la virgoletta di chiusura
        }

        Some(Token::Attribute(key.trim().to_string(), value))
    }

    // Gestisce tutto ciò che sta dopo '<nome' fino a '>' incluso:
    // eventuali attributi finiscono in `pending`.
    // Ritorna true se il tag è self-closing (es. <br/>)
    fn read_tag_body(&mut self) -> bool {
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some('/') => {
                    self.advance(); // salta '/'
                    self.skip_whitespace();
                    if self.peek() == Some('>') {
                        self.advance(); // salta '>'
                    }
                    return true; // self-closing
                }
                Some('>') => {
                    self.advance(); // salta '>'
                    return false;
                }
                Some(_) => {
                    if let Some(attr_token) = self.read_attribute() {
                        self.pending.push_back(attr_token);
                    } else {
                        // niente di leggibile, evita loop infinito
                        self.advance();
                    }
                }
                None => return false, // EOF inatteso, file troncato
            }
        }
    }

    pub fn next_token(&mut self) -> Token {
        // Se abbiamo già token pronti (es. attributi), restituiscili prima
        if let Some(tok) = self.pending.pop_front() {
            return tok;
        }

        self.skip_whitespace();

        let c = match self.peek() {
            Some(ch) => ch,
            None => return Token::EOF,
        };

        match c {
            '<' => {
                self.advance(); // salta '<'

                if self.peek() == Some('/') {
                    self.advance(); // salta '/'
                    let name = self.read_until_space_or_bracket();
                    self.skip_whitespace();
                    if self.peek() == Some('>') {
                        self.advance(); // salta '>'
                    }
                    return Token::TagClose(name);
                }

                let name = self.read_until_space_or_bracket();
                let self_closing = self.read_tag_body();

                if self_closing {
                    // Trattiamo <br/> come TagOpen seguito subito da TagClose,
                    // così il parser (stack-based) non lo lascia mai aperto.
                    self.pending.push_back(Token::TagClose(name.clone()));
                }

                Token::TagOpen(name)
            }
            _ => {
                let start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch == '<' {
                        break;
                    }
                    self.advance();
                }
                Token::Text(self.input[start..self.pos].to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenizer_basic_tags() {
        let mut tokenizer = Tokenizer::new("<div></div>");
        assert_eq!(tokenizer.next_token(), Token::TagOpen("div".to_string()));
        assert_eq!(tokenizer.next_token(), Token::TagClose("div".to_string()));
        assert_eq!(tokenizer.next_token(), Token::EOF);
    }

    #[test]
    fn test_tokenizer_with_text() {
        let mut tokenizer = Tokenizer::new("<div>Hello</div>");
        assert_eq!(tokenizer.next_token(), Token::TagOpen("div".to_string()));
        assert_eq!(tokenizer.next_token(), Token::Text("Hello".to_string()));
        assert_eq!(tokenizer.next_token(), Token::TagClose("div".to_string()));
    }

    #[test]
    fn test_tokenizer_with_attributes() {
        let mut tokenizer = Tokenizer::new(r#"<div class="container" id="main"></div>"#);
        assert_eq!(tokenizer.next_token(), Token::TagOpen("div".to_string()));
        assert_eq!(
            tokenizer.next_token(),
            Token::Attribute("class".to_string(), "container".to_string())
        );
        assert_eq!(
            tokenizer.next_token(),
            Token::Attribute("id".to_string(), "main".to_string())
        );
        assert_eq!(tokenizer.next_token(), Token::TagClose("div".to_string()));
    }

    #[test]
    fn test_tokenizer_self_closing() {
        let mut tokenizer = Tokenizer::new(r#"<div><br/></div>"#);
        assert_eq!(tokenizer.next_token(), Token::TagOpen("div".to_string()));
        assert_eq!(tokenizer.next_token(), Token::TagOpen("br".to_string()));
        assert_eq!(tokenizer.next_token(), Token::TagClose("br".to_string()));
        assert_eq!(tokenizer.next_token(), Token::TagClose("div".to_string()));
    }

    #[test]
    fn test_tokenizer_utf8() {
        let mut tokenizer = Tokenizer::new("<p>città è bella</p>");
        assert_eq!(tokenizer.next_token(), Token::TagOpen("p".to_string()));
        assert_eq!(
            tokenizer.next_token(),
            Token::Text("città è bella".to_string())
        );
        assert_eq!(tokenizer.next_token(), Token::TagClose("p".to_string()));
    }

    #[test]
    fn test_tokenizer_empty_input() {
        let mut tokenizer = Tokenizer::new("");
        assert_eq!(tokenizer.next_token(), Token::EOF);
    }

    #[test]
    fn test_tokenizer_self_closing_with_attribute() {
        let mut tokenizer = Tokenizer::new(r#"<img src="foo.png"/>"#);
        assert_eq!(tokenizer.next_token(), Token::TagOpen("img".to_string()));
        assert_eq!(
            tokenizer.next_token(),
            Token::Attribute("src".to_string(), "foo.png".to_string())
        );
        assert_eq!(tokenizer.next_token(), Token::TagClose("img".to_string()));
    }
}