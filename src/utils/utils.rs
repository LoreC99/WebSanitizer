use crate::scheduler::workers::{Job, ThreadPool};

/// Esplora ricorsivamente una directory e invia ogni file trovato al ThreadPool
pub fn explore_directory(dir: &std::path::Path, pool: &ThreadPool) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    pool.execute(Job::File(path_str.to_string()));
                }
            } else if path.is_dir() {
                // Chiamata ricorsiva per le sottocartelle
                explore_directory(&path, pool);
            }
        }
    } else {
        eprintln!("⚠️ Impossibile leggere la directory: {:?}", dir);
    }
}