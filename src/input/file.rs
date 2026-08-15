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
    pub async fn read(&self, path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
        // 1. Ispezione preventiva: otteniamo i metadati dal file system
        // senza caricare effettivamente il file in memoria.
        let file_metadata = fs::metadata(path).await?;

        // 2. Prevenzione DoS: se la dimensione supera il budget, blocchiamo tutto subito.
        if file_metadata.len() > self.max_bytes {
            return Err("Il file è più grande della dimensione massima consentita".into())
        }

        // 3. Lettura: ora che siamo sicuri che il file rispetta i limiti, lo carichiamo in RAM.
        let file = read(path).await?;

        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

    // Helper: Crea un percorso per un file temporaneo sicuro in base al sistema operativo
    fn get_temp_path(filename: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("web_sanitizer_test_{}", filename));
        path
    }


    #[tokio::test]
    async fn test_read_blocca_file_troppo_grandi() {
        let path = get_temp_path("too_big.html");

        // 1. Scriviamo un file di 20 byte
        fs::write(&path, "01234567890123456789").await.unwrap();

        // 2. Impostiamo il limite a soli 10 byte (DoS prevention)
        let reader = FileReader::new(10);
        let result = reader.read(&path).await;

        // 3. Verifichiamo che venga bloccato PRIMA di leggerlo
        assert!(result.is_err(), "Il file troppo grande deve generare un errore");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Il file è più grande della dimensione massima consentita"
        );

        // 4. Pulizia
        fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn test_read_gestisce_file_inesistenti() {
        // Percorso volutamente inventato
        let path = Path::new("/percorso/assolutamente/falso/file.html");

        let reader = FileReader::new(1024);
        let result = reader.read(&path).await;

        // Deve fallire elegantemente sul controllo di fs::metadata senza fare panic
        assert!(result.is_err(), "La lettura di un file inesistente deve restituire un errore");
    }

    #[tokio::test]
    async fn test_read_gestisce_file_non_utf8() {
        let path = get_temp_path("invalid_utf8.bin");

        // 1. Scriviamo byte non validi (il byte \xFF non è un carattere testuale UTF-8)
        let bad_bytes: &[u8] = b"Test \xFF fallito";
        fs::write(&path, bad_bytes).await.unwrap();

        let reader = FileReader::new(1024);
        let result = reader.read(&path).await;

        // 2. Il programma non deve crashare e deve restituire i byte crudi.
        assert!(result.is_ok());
        let bytes_letti = result.unwrap();

        // Verifichiamo che il lettore abbia recuperato i byte esatti
        assert_eq!(bytes_letti, bad_bytes);

        // Simuliamo ciò che fa il worker: from_utf8_lossy deve sostituire il byte rotto con il simbolo (U+FFFD)
        let stringa_letta = String::from_utf8_lossy(&bytes_letti).to_string();
        assert!(stringa_letta.contains('\u{FFFD}'), "Il carattere invalido doveva essere rimpiazzato dal simbolo di fallback");

        // 3. Pulizia
        fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn test_read_file_success() {
        let path = get_temp_path("success.html");

        // 1. Creiamo un file temporaneo valido
        fs::write(&path, "<html><body>Tutto OK</body></html>").await.unwrap();

        // 2. Leggiamo il file con un limite di byte ampio (1024)
        let reader = FileReader::new(1024);
        let result = reader.read(&path).await;

        // 3. Verifichiamo il risultato (ora confrontiamo con un array di byte usando b"...")
        assert!(result.is_ok(), "La lettura del file valido deve avere successo");
        assert_eq!(result.unwrap(), b"<html><body>Tutto OK</body></html>");

        // 4. Pulizia
        fs::remove_file(&path).await.unwrap();
    }
}