use std::error::Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use reqwest::Client;
use futures_util::StreamExt;

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
    /// Inizializza il fetcher applicando un timeout globale di sicurezza.
    pub fn new(max_bytes: u64, max_depth: u8, max_request: u32, timeout: Duration) -> Result<Self, reqwest::Error> {
        // Configuriamo il client con il builder per impostare il timeout prima della creazione
        let client = Client::builder().timeout(timeout).build()?;

        // Restituisce l'istanza sfruttando la sintassi compatta di Rust
        Ok(Self { client, max_bytes, max_depth, max_request, current_requests: AtomicU32::new(0) })
    }

    pub async fn fetch(&self, url: &str, current_depth: u8) -> Result<String, Box<dyn Error>> {
        // 1. Check Profondità
        if current_depth > self.max_depth {
            return Err("Limite profondità superato".into());
        }

        // 2. Check Richieste e incremento atomico in un solo colpo
        // fetch_add aggiunge 1 e restituisce il valore PRECEDENTE all'aggiunta
        let req_count = self.current_requests.fetch_add(1, Ordering::Relaxed);
        if req_count > self.max_request {
            return Err("Limite richieste superato".into());
        }
        // 3. Facciamo la richiesta
        let response = self.client.get(url).send().await?.error_for_status()?;

        // 4. Otteniamo lo stream (che implementa il trait Stream)
        let mut stream = response.bytes_stream();

        let mut downloaded_bytes = Vec::new();
        let mut total_size: u64 = 0;

        // 5. next() esiste SOLO grazie a use futures::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?; // chunk è di tipo bytes::Bytes
            let chunk_size = chunk.len() as u64;

            if total_size + chunk_size > self.max_bytes {
                // Sforato il limite! Interrompiamo tutto.
                // (Nota: in un progetto reale qui creeresti un tuo errore custom,
                // ma per ora puoi usare un panic o restituire un errore formattato)
                return Err("Attenzione: Il file supera il limite di byte (DoS prevention)!".into());
            }

            total_size += chunk_size;
            downloaded_bytes.extend_from_slice(&chunk);
        }

        // 6. Se arriviamo qui senza errori, il file è sicuro ed entro i limiti.
        // Convertiamo i byte in Stringa (se non è UTF-8 valido, per ora la sostituiamo con caratteri sicuri)
        let html_string = String::from_utf8_lossy(&downloaded_bytes).to_string();

        Ok(html_string)
    }
}

