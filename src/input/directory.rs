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
                        if found_files.len() >= self.max_files {
                            break;
                        }
                    }
                }
            }
        }
        Ok(found_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    // Helper: Crea una cartella univoca per ogni test e si assicura che sia pulita
    fn setup_test_dir(test_name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("websanitizer_dir_test_{}", test_name));

        // Se la cartella esiste da un test precedente fallito, la pialla via
        let _ = fs::remove_dir_all(&path);

        // Crea la cartella nuova e vuota
        fs::create_dir_all(&path).expect("Impossibile creare la cartella di test");
        path
    }

    #[test]
    fn test_scan_filtra_estensioni_correttamente() {
        let dir = setup_test_dir("estensioni");

        // Creiamo file misti
        fs::write(dir.join("pagina1.html"), "").unwrap();
        fs::write(dir.join("stile.css"), "").unwrap();
        fs::write(dir.join("script.js"), "").unwrap();
        fs::write(dir.join("pagina2.htm"), "").unwrap();

        let estensioni_valide = vec!["html".to_string(), "htm".to_string()];
        let scanner = DirectoryScanner::new(estensioni_valide, 10, 100);

        let result = scanner.scan(&dir).unwrap();

        // Deve trovare solo i 2 file HTML/HTM
        assert_eq!(result.len(), 2, "Il filtro delle estensioni non ha funzionato correttamente");

        // Pulizia
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_scan_rispetta_limite_profondità() {
        let root_dir = setup_test_dir("profondità");

        // Livello 1 (Radice)
        fs::write(root_dir.join("livello1.html"), "").unwrap();

        // Livello 2 (Sottocartella)
        let sub_dir = root_dir.join("sub");
        fs::create_dir(&sub_dir).unwrap();
        fs::write(sub_dir.join("livello2.html"), "").unwrap();

        // Livello 3 (Sotto-sottocartella)
        let sub_sub_dir = sub_dir.join("subsub");
        fs::create_dir(&sub_sub_dir).unwrap();
        fs::write(sub_sub_dir.join("livello3.html"), "").unwrap();

        let estensioni_valide = vec!["html".to_string()];

        // Impostiamo max_depth a 2 (esplora root + 1 sottocartella)
        let scanner = DirectoryScanner::new(estensioni_valide, 2, 100);
        let result = scanner.scan(&root_dir).unwrap();

        // Deve trovare livello 1 e livello 2, ma ignorare livello 3
        assert_eq!(result.len(), 2, "Il limite di profondità non è stato rispettato");

        // Pulizia
        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn test_scan_rispetta_limite_massimo_file_dos() {
        let dir = setup_test_dir("max_files");

        // Creiamo 5 file validi
        for i in 0..5 {
            fs::write(dir.join(format!("file_{}.html", i)), "").unwrap();
        }

        let estensioni_valide = vec!["html".to_string()];

        // Limite di emergenza: massimo 3 file
        let scanner = DirectoryScanner::new(estensioni_valide, 10, 3);
        let result = scanner.scan(&dir).unwrap();

        // Il ciclo deve essersi interrotto esattamente a 3
        assert_eq!(result.len(), 3, "La prevenzione DoS (max_files) ha fallito");

        // Pulizia
        let _ = fs::remove_dir_all(dir);
    }
}
