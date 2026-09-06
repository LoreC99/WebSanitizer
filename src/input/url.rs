use std::error::Error;
use std::sync::Mutex;
use std::time::Duration;
use reqwest::Client;
use futures_util::StreamExt;
use reqwest::redirect::Policy;

use crate::sanitizer::url_rules::UrlValidator;
use crate::sanitizer::resource_rules::{ResourceGuard, RefusalReason};

/// Gestisce il download asincrono delle risorse web applicando limiti di sicurezza.
pub struct UrlFetcher {
    /// Client HTTP riutilizzabile (sfrutta il connection pooling per le performance).
    client: Client,
    /// Guardiano centralizzato per la gestione dei limiti di rete e DoS.
    guard: Mutex<ResourceGuard>,
}

impl UrlFetcher {
    /// Inizializza il fetcher passando direttamente il ResourceGuard configurato.
    pub fn new(guard: ResourceGuard, timeout: Duration) -> Result<Self, reqwest::Error> {
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

        Ok(Self {
            client,
            guard: Mutex::new(guard)
        })
    }

    pub async fn fetch(&self, url: &str, current_depth: u8) -> Result<Vec<u8>, Box<dyn Error + '_>> {
        // ==========================================================
        // Validazione preventiva dell'URL iniziale
        // ==========================================================
        UrlValidator::is_safe_redirect_hop(url)?;

        // 1. Controlli Preventivi tramite ResourceGuard (Profondità, Flag Attivo, Richieste massime)
        {
            // Usiamo unwrap() per evitare il conflitto del PoisonError con Box<dyn Error>
            let mut g = self.guard.lock()?;

            if let Err(refusal) = g.check_before_fetch(current_depth as usize) {
                // Implementazione esplicita della RefusalReason
                let err_msg = match refusal {
                    RefusalReason::FetchingDisabled =>
                        "FETCH_DISABLED: Il download delle risorse esterne è disabilitato dalla policy.".to_string(),
                    RefusalReason::MaxDepthExceeded { current, limit } =>
                        format!("MAX_DEPTH_EXCEEDED: La profondità attuale ({}) supera il limite ({})", current, limit),
                    RefusalReason::MaxRequestsExceeded { current, limit } =>
                        format!("MAX_REQUESTS_EXCEEDED: Raggiunte le {} richieste (limite massimo: {})", current, limit),
                    _ => format!("POLICY_REJECTED: {:?}", refusal), // Fallback per altre varianti non di rete
                };
                return Err(err_msg.into());
            }

            // Se i controlli passano, registriamo subito che stiamo facendo una nuova richiesta
            g.record_request();
        }

        // 2. Facciamo la richiesta
        let response = self.client.get(url).send().await?.error_for_status()?;

        // 3. Controllo Preventivo dell'Header Content-Type
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
        let mut total_size: usize = 0;

        // 5. Download a chunk e Prevenzione DoS in tempo reale tramite ResourceGuard
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            total_size += chunk.len();

            // Interroghiamo il guardiano per sapere se abbiamo superato i byte massimi
            {
                let g = self.guard.lock()?;
                if let Err(refusal) = g.check_response_size(total_size) {
                    // Implementazione esplicita per il blocco DoS
                    let err_msg = match refusal {
                        RefusalReason::ResourceTooLarge { size, limit } =>
                            format!("RESOURCE_TOO_LARGE: Il payload di {} byte supera il limite DoS di {}", size, limit),
                        _ => format!("DOS_PREVENTION_BLOCKED: {:?}", refusal),
                    };
                    return Err(err_msg.into());
                }
            }

            downloaded_bytes.extend_from_slice(&chunk);
        }

        Ok(downloaded_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    // Assicurati di importare la policy usata nel costruttore di ResourceGuard
    use crate::config::loader::ResourcePolicy;

    // Funzione helper aggiornata per creare un UrlFetcher base per i test
    fn create_test_fetcher(max_bytes: u64, max_depth: u8, max_request: u32) -> UrlFetcher {
        // Creiamo una policy mockata per far funzionare il test
        let mock_policy = ResourcePolicy {
            fetch_resources: true,
            // (aggiungi qui altri campi obbligatori di ResourcePolicy se necessario)
        };

        let guard = ResourceGuard::new(mock_policy, max_depth, max_request, max_bytes);
        UrlFetcher::new(guard, Duration::from_secs(2))
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

        let fetcher = create_test_fetcher(1024, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"<html>Successo</html>");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_profondità() {
        let fetcher = create_test_fetcher(1024, 2, 10);
        let result = fetcher.fetch("http://finto.com", 3).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MAX_DEPTH_EXCEEDED"));
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_richieste() {
        let mut server = Server::new_async().await;
        let _mock = server.mock("GET", "/test").with_status(200).create_async().await;
        let url = format!("{}/test", server.url());

        // Limite massimo: 1 richiesta
        let fetcher = create_test_fetcher(1024, 5, 1);
        let _ = fetcher.fetch(&url, 0).await;
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MAX_REQUESTS_EXCEEDED"));
    }

    #[tokio::test]
    async fn test_fetch_blocca_limite_byte_dos() {
        let mut server = Server::new_async().await;
        let body = "A".repeat(20);
        let mock = server.mock("GET", "/heavy")
            .with_status(200)
            .with_body(body)
            .create_async().await;

        let url = format!("{}/heavy", server.url());

        // Accetta max 10 byte
        let fetcher = create_test_fetcher(10, 5, 10);
        let result = fetcher.fetch(&url, 0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RESOURCE_TOO_LARGE"));
        mock.assert_async().await;
    }

    // Gli altri test rimangono validi (test_fetch_gestisce_errori_http, test_fetch_rejects_declared_javascript)
}
