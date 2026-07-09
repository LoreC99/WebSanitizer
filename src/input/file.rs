use std::error::Error;
use std::path::Path;
use tokio::fs;
use tokio::fs::read;
use std::string::String;

/// Gestisce la lettura asincrona dei file locali applicando limiti di sicurezza.
pub struct FileReader {
    /// Dimensione massima consentita in byte per il file.
    /// Previene attacchi DoS (saturazione della memoria RAM).
    max_bytes: u64
}

impl FileReader {
    /// Inizializza il lettore impostando il limite di sicurezza.
    pub fn new(max_bytes: u64) -> Self {
        Self { max_bytes }
    }

    /// Legge il file in modo difensivo e restituisce il suo contenuto come stringa.
    pub async fn read(&self, path: &Path) -> Result<String, Box<dyn Error>> {
        // 1. Ispezione preventiva: otteniamo i metadati dal file system
        // senza caricare effettivamente il file in memoria.
        let file_metadata = fs::metadata(path).await?;

        // 2. Prevenzione DoS: se la dimensione supera il budget, blocchiamo tutto subito.
        if file_metadata.len() > self.max_bytes {
            return Err("Il file è più grande della dimensione massima consentita".into())
        }

        // 3. Lettura: ora che siamo sicuri che il file rispetta i limiti, lo carichiamo in RAM.
        let file = read(path).await?;

        // 4. Decodifica robusta: convertiamo i byte in stringa sostituendo eventuali
        // byte non UTF-8 con caratteri speciali (), evitando panic se il file è binario.
        let html_string = String::from_utf8_lossy(&file).to_string();

        Ok(html_string)
    }
}