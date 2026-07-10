use std::collections::HashMap;

pub struct CompositionGraph {
    edges: HashMap<String, Vec<String>>,
}

impl CompositionGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    pub fn add_dependency(&mut self, verifier: &str, depends_on: &str) {
        self.edges
            .entry(verifier.to_string())
            .or_default()
            .push(depends_on.to_string());
    }

    pub fn dependencies_of(&self, verifier: &str) -> Vec<&str> {
        self.edges
            .get(verifier)
            .map(|deps| deps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

impl Default for CompositionGraph {
    fn default() -> Self {
        Self::new()
    }
}
