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
    pub block_meta_refresh: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    // Helper: Crea un percorso per un file temporaneo sicuro
    fn get_temp_path(filename: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("websanitizer_loader_{}", filename));
        path
    }

    #[test]
    fn test_load_policy_success() {
        let path = get_temp_path("valid.toml");

        // 1. Scriviamo un file TOML valido su disco
        let toml_content = r#"
            [html]
            allow_scripts = true
            remove_iframes = false
            allowed_tags = ["html", "p", "a"]

            [url]
            allowed_schemes = ["https", "mailto"]
            block_data_uris = true
            block_javascript_uris = true

            [resources]
            fetch_resources = true
            max_depth = 3
            max_resource_size = 5000
        "#;
        fs::write(&path, toml_content).expect("Impossibile creare il file TOML di test");

        // 2. Testiamo la funzione
        let result = load_policy(&path);

        // 3. Verifiche
        assert!(result.is_ok(), "Il file TOML valido non è stato caricato correttamente");
        let policy = result.unwrap();

        assert_eq!(policy.html.allow_scripts, true);
        assert_eq!(policy.url.allowed_schemes, vec!["https", "mailto"]);
        assert_eq!(policy.resources.max_depth, 3);
        assert_eq!(policy.resources.max_resource_size, 5000);

        // 4. Pulizia
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_load_policy_file_not_found() {
        // Passiamo un percorso che siamo sicuri non esista
        let result = load_policy("percorso/inventato/inesistente.toml");

        // Deve fallire in modo controllato (Result::Err) e non fare panic
        assert!(result.is_err(), "Caricare un file inesistente deve restituire un errore");
    }

    #[test]
    fn test_load_policy_malformed_toml() {
        let path = get_temp_path("malformed.toml");

        // 1. Scriviamo un file con sintassi TOML completamente errata
        let bad_content = r#"
            [html
            allow_scripts = "questa_dovrebbe_essere_una_booleana"
            missing_brackets = true
        "#;
        fs::write(&path, bad_content).expect("Impossibile creare il file");

        // 2. Testiamo la funzione
        let result = load_policy(&path);

        // 3. Verifichiamo che toml::from_str catturi l'errore
        assert!(result.is_err(), "Un file TOML malformato deve restituire un errore di parsing");

        // 4. Pulizia
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_default_policy_loads_without_panic() {
        // Questo test è semplicissimo ma fondamentale.
        // Se il file strict.toml specificato in `include_str!` è malformato,
        // toml::from_str(...).expect(...) farà crashare (panic) questo test.
        // Se il test passa, significa che la policy di default è sintatticamente perfetta.

        let policy = default_policy();

        // Facciamo un sanity check su un paio di valori che ci aspettiamo in una policy strict
        assert_eq!(policy.html.allow_scripts, false, "La policy di default dovrebbe vietare gli script");
        assert_eq!(policy.html.remove_iframes, true, "La policy di default dovrebbe rimuovere gli iframe");
    }
}