use std::error::Error;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct DirectoryScanner {
    /// Lista delle estensioni consentite (es. "html", "htm").
    /// Filtra i file irrilevanti alla fonte.
    allowed_extensions: Vec<String>,

    /// Previene l'esplorazione infinita (DoS da I/O).
    max_depth: usize,

    /// Previene l'esaurimento della memoria (DoS da RAM).
    max_files: usize,
}

impl DirectoryScanner {
    pub fn new(allowed_extensions: Vec<String>, max_depth: usize, max_files: usize) -> Self {
        Self {
            allowed_extensions,
            max_depth,
            max_files,
        }
    }

    pub fn scan(&self, target_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
        // Applichiamo il limite di profondità
        let directory_tree = WalkDir::new(target_dir).max_depth(self.max_depth);
        let mut found_files = Vec::new();

        for entry in directory_tree {
            let entry = entry?;
            let file_type = entry.file_type();

            // PREVENZIONE PATH-TRAVERSAL:
            // Ci assicuriamo che sia un file e NON un symlink.
            if file_type.is_file() && !file_type.is_symlink() {
                let path = entry.path();

                // Estrazione sicura e match dell'estensione
                if let Some(ext_str) = path.extension().and_then(|os_str| os_str.to_str()) {
                    if self.allowed_extensions.iter().any(|e| e == ext_str) {
                        found_files.push(path.to_path_buf());

                        // PREVENZIONE DoS (RAM Exhaustion):
                        if found_files.len() > self.max_files {
                            break;
                        }
                    }
                }
            }
        }
        Ok(found_files)
    }
}
