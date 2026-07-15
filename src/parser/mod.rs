pub mod html;
pub mod tokenizer;

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

    pub fn add_child(&mut self, child: Node) -> Result<(), &'static str> {
        match self {
            Node::Element { children, .. } => {
                children.push(child);
                Ok(())
            }
            Node::Text(_) => Err("cannot add child to a Text node"),
        }
    }
}