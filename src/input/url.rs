use std::error::Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use reqwest::Client;
use futures_util::StreamExt;
use crate::sanitizer::url_rules::UrlValidator;
use reqwest::redirect::Policy;

/// Gestisce il download asincrono delle risorse web applicando limiti di sicurezza.
pub struct UrlFetcher {
    /// Client HTTP riutilizzabile (sfrutta il connection pooling per le performance).
    client: Client,
    /// Limite massimo di dimensione per singola risorsa (prevenzione DoS).
    max_bytes: u64,
    /// Limite di ricorsione per le sotto-risorse (es. CSS che importano altri CSS).
    max_depth: u8,
    /// Limite massimo di richieste di rete per singolo documento elaborato.
    max_request: u32,
    /// Tiene traccia delle richieste fatte finora
    current_requests: AtomicU32,
}

impl UrlFetcher {
    /// Inizializza il fetcher applicando un timeout globale di sicurezza e la policy di redirect.
    pub fn new(max_bytes: u64, max_depth: u8, max_request: u32, timeout: Duration) -> Result<Self, reqwest::Error> {
        // Configuriamo una policy personalizzata per i redirect
        let custom_redirect_policy = Policy::custom(|attempt| {
            // Controlliamo il nuovo URL in ogni salto del redirect
            match UrlValidator::is_safe_redirect_hop(attempt.url().as_str()) {
                Ok(_) => attempt.follow(), // URL sicuro, segui il redirect
                Err(e) => {
                    eprintln!("Bloccato redirect sospetto: {}", e);
                    attempt.error(e) // Blocca immediatamente la catena
                }
            }
        });

        // Configuriamo il client con builder aggiungendo la nostra policy
        let client = Client::builder()
            .timeout(timeout)
            .redirect(custom_redirect_policy) 
            .build()?;

        Ok(Self { client, max_bytes, max_depth, max_request, current_requests: AtomicU32::new(0) })
    }

    pub async fn fetch(&self, url: &str, current_depth: u8) -> Result<Vec<u8>, Box<dyn Error>> {
        // ==========================================================
        // Validazione preventiva dell'URL iniziale
        // ==========================================================
        UrlValidator::is_safe_redirect_hop(url)?;

        // 1. Check Profondità
        if current_depth > self.max_depth {
            return Err("Limite profondità superato".into());
        }

        // 2. Check Richieste
        let req_count = self.current_requests.fetch_add(1, Ordering::Relaxed);
        if req_count >= self.max_request {
            return Err("Limite richieste superato".into());
        }

        // 3. Facciamo la richiesta
        let response = self.client.get(url).send().await?.error_for_status()?;

        // 3.5. Controllo Preventivo dell'Header Content-Type
        if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            if let Ok(ct_str) = content_type.to_str() {
                let ct_lower = ct_str.to_lowercase();
                if ct_lower.contains("javascript") {
                    return Err("MIME_TYPE_REJECTED: Il server ha dichiarato un tipo di contenuto attivo (JavaScript)".into());
                }
            }
        }

        // 4. Otteniamo lo stream
        let mut stream = response.bytes_stream();
        let mut downloaded_bytes = Vec::new();
        let mut total_size: u64 = 0;

        // 5. Check dimensione e download (DoS prevention)
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            let chunk_size = chunk.len() as u64;

            if total_size + chunk_size > self.max_bytes {
                return Err("Attenzione: Il file supera il limite di byte (DoS prevention)!".into());
            }

            total_size += chunk_size;
            downloaded_bytes.extend_from_slice(&chunk);
        }

        Ok(downloaded_bytes)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    // Funzione helper per creare un UrlFetcher base per i test
    fn create_test_fetcher(max_bytes: u64, max_depth: u8, max_request: u32) -> UrlFetcher {
        UrlFetcher::new(max_bytes, max_depth, max_request, Duration::from_secs(2))
            .expect("Errore nella creazione del fetcher di test")
    }

    #[tokio::test]
    async fn test_fetch_success() {
        let mut server = Server::new_async().await;
        let mock = server.mock("GET", "/test")
            .with_status(200)
            .with_header("content-type", "text/html")
            .with_body("<html>Successo</html>")
            .create_async().await;

        let url = format!("{}/test", server.url());

        // Limiti ampi per far passare la richiesta
        let fetcher = create_test_fetcher(1024, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_ok());
        // Ora confrontiamo con un array di byte crudi (b"...")
        assert_eq!(result.unwrap(), b"<html>Successo</html>");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_profondità() {
        // Profondità massima 2
        let fetcher = create_test_fetcher(1024, 2, 10);

        // Proviamo a passare una profondità attuale di 3
        let result = fetcher.fetch("http://finto.com", 3).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Limite profondità superato");
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_richieste() {
        let mut server = Server::new_async().await;
        let _mock = server.mock("GET", "/test").with_status(200).create_async().await;
        let url = format!("{}/test", server.url());

        // Limite massimo: 1 richiesta
        let fetcher = create_test_fetcher(1024, 5, 1);

        // La prima richiesta deve passare (il contatore va a 1)
        let _ = fetcher.fetch(&url, 0).await;

        // La seconda richiesta deve fallire
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Limite richieste superato");
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_byte_dos() {
        let mut server = Server::new_async().await;

        // Simuliamo un server che invia una stringa di 20 byte
        let body = "A".repeat(20);
        let mock = server.mock("GET", "/heavy")
            .with_status(200)
            .with_body(body)
            .create_async().await;

        let url = format!("{}/heavy", server.url());

        // Configuriamo il fetcher per accettare al massimo 10 byte
        let fetcher = create_test_fetcher(10, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("limite di byte"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_gestisce_errori_http() {
        let mut server = Server::new_async().await;
        // Simuliamo un errore 500 del server
        let mock = server.mock("GET", "/error")
            .with_status(500)
            .create_async().await;

        let url = format!("{}/error", server.url());

        let fetcher = create_test_fetcher(1024, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        // Non deve crashare (panic), ma restituire Err grazie a error_for_status()
        assert!(result.is_err());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_rejects_declared_javascript() {
        let mut server = Server::new_async().await;

        // Simuliamo un server che restituisce un file di testo innocuo
        // ma dichiara malignamente (o per errore) che si tratta di JavaScript
        let mock = server.mock("GET", "/finto-script")
            .with_status(200)
            .with_header("content-type", "text/javascript; charset=utf-8")
            .with_body("Questo è solo testo innocuo")
            .create_async().await;

        let url = format!("{}/finto-script", server.url());

        let fetcher = create_test_fetcher(1024, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        // Il fetcher deve restituire errore PRIMA di scaricare il corpo
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MIME_TYPE_REJECTED"));
        mock.assert_async().await;
    }
}

