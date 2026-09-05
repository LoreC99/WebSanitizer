pub mod html;

#[derive(Debug, PartialEq)]
pub enum Node {
    Element {
        name: String,
        attributes: Vec<(String, String)>,
        children: Vec<Node>,
    },
    Text(String),
}

impl Node {
    // --- Costruttori ---

    pub fn element(name: impl Into<String>) -> Self {
        Node::Element {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn text(content: impl Into<String>) -> Self {
        Node::Text(content.into())
    }

    // --- Accessor / Mutator ---

    pub fn name(&self) -> Option<&str> {
        match self {
            Node::Element { name, .. } => Some(name),
            Node::Text(_) => None,
        }
    }

    pub fn children(&self) -> &[Node] {
        match self {
            Node::Element { children, .. } => children,
            Node::Text(_) => &[],
        }
    }
    /// Il metodo 'add_child' permette di costruire la gerarchia
    pub fn add_child(&mut self, child: Node) -> Result<(), &'static str> {
        match self {
            Node::Element { children, .. } => {
                children.push(child);
                Ok(())
            }
            Node::Text(_) => Err("cannot add child to a Text node"),
        }
    }

    /// Ricostruisce la stringa HTML a partire dall'albero DOM
    pub fn to_html_string(&self) -> String {
        match self {
            // Se è un nodo di testo, restituiamo semplicemente il contenuto
            Node::Text(content) => content.clone(),

            // Se è un elemento HTML, lo formattiamo con tag, attributi e figli
            Node::Element { name, attributes, children } => {
                let mut html = format!("<{}", name);

                // 1. Aggiungiamo gli attributi (es: class="box")
                for (key, value) in attributes {
                    // Nota: In un caso reale di produzione, qui si dovrebbe fare l'escape
                    // delle virgolette dentro `value` per sicurezza.
                    html.push_str(&format!(" {}=\"{}\"", key, value));
                }

                // 2. Gestione dei "Void Elements" (Tag vuoti)
                // In HTML, alcuni tag come <img> o <br> non hanno un tag di chiusura.
                let void_elements = [
                    "area", "base", "br", "col", "embed", "hr", "img",
                    "input", "link", "meta", "param", "source", "track", "wbr"
                ];

                if void_elements.contains(&name.as_str()) {
                    // Chiudiamo semplicemente il tag e ci fermiamo qui
                    html.push_str(">");
                } else {
                    // Chiudiamo il tag di apertura
                    html.push_str(">");

                    // 3. RICORSIONE: Elaboriamo tutti i figli
                    for child in children {
                        html.push_str(&child.to_html_string());
                    }

                    // 4. Aggiungiamo il tag di chiusura
                    html.push_str(&format!("</{}>", name));
                }

                html
            }
        }
    }
}