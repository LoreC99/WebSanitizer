use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::error::Error;

// ==========================================
// 1. Definizione delle Strutture Dati
// ==========================================

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    pub html: HtmlPolicy,
    pub url: UrlPolicy,
    pub resources: ResourcePolicy,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HtmlPolicy {
    pub allow_scripts: bool,
    pub remove_iframes: bool,
    pub allowed_tags: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UrlPolicy {
    pub allowed_schemes: Vec<String>,
    pub block_data_uris: bool,
    pub block_javascript_uris: bool,
    pub blocklist_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResourcePolicy {
    pub fetch_resources: bool,
    pub max_depth: u8,
    pub max_resource_size: u64,
}

// ==========================================
// 2. Funzioni di Caricamento
// ==========================================

/// Carica una policy da un file TOML specificato dall'utente.
/// Restituisce un Result per permettere al chiamante di gestire eventuali errori
/// (es. file non trovato, permessi negati, TOML malformato).
pub fn load_policy<P: AsRef<Path>>(path: P) -> Result<Policy, Box<dyn Error>> {
    // Legge l'intero contenuto del file in una stringa
    let content = fs::read_to_string(path)?;

    // Deserializza la stringa TOML nella struttura Rust
    let policy: Policy = toml::from_str(&content)?;

    Ok(policy)
}

/// Carica la policy di default, che viene incorporata direttamente nel binario
/// al momento della compilazione. Questo garantisce che il programma abbia
/// sempre una configurazione di base sicura e funzionante.
pub fn default_policy() -> Policy {
    // include_str! legge il file durante `cargo build` e lo inserisce come &str nel binario
    let default_toml = include_str!("../../policies/strict.toml");

    // Possiamo usare .expect() qui perché se il file di default è malformato,
    // è un errore dello sviluppatore (tuo), non dell'utente, ed è giusto che il programma fallisca in modo rumoroso.
    toml::from_str(default_toml).expect("ERRORE INTERNO: Il file strict.toml è malformato")
}