// use WebSanitizer::cli::cli::Cli;
use axum::{routing::post, Router, Json};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use std::time::Duration;
use WebSanitizer::config::loader;
use WebSanitizer::input::url::UrlFetcher;

#[tokio::main]
async fn main() {

    println!("=== Avvio Web Sanitizer ===\n");
    // Creiamo il "router", ovvero la mappa degli indirizzi del nostro server
    let app = Router::new()
        .route("/v1/resources", post(process_resource));

    // Ci mettiamo in ascolto sulla porta 3000 di localhost
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("🚀 Web Sanitizer in ascolto su http://localhost:3000");
    println!("In attesa di richieste da curl...\n");

    // Avviamo il server in un loop infinito
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct SanitizeRequest {
    url: String,
}

#[derive(Serialize)]
struct SanitizeReport {
    status: String,
    original_url: String,
    sanitized_html: String,
    message: String,
}

async fn process_resource(Json(payload): Json<SanitizeRequest>) -> Json<SanitizeReport> {
    println!("⚡ RICEVUTA RICHIESTA!");
    println!("-> Target da scaricare: {}", payload.url);

    // 1. Carichiamo la policy (es. quella di default strict)
    let policy = loader::default_policy();

    // 2. Inizializziamo il fetcher con i limiti presi dalla policy
    // (Adatta i parametri al costruttore del tuo UrlFetcher)
    let fetcher = UrlFetcher::new(
        policy.resources.max_resource_size,
        policy.resources.max_depth,
        10, // max_requests di test
        Duration::from_secs(5),
    ).expect("Impossibile creare il UrlFetcher");

    // 3. Scarichiamo l'HTML malevolo da evil-origin
    // NOTA: Se hai lasciato il blocco SSRF attivo su localhost, per questo test dovrai disattivarlo
    // o temporaneamente commentarlo in `is_safe_url` per permettere la connessione a localhost:3100!
    match fetcher.fetch(&payload.url, 0).await {
        Ok(raw_html) => {
            println!("-> HTML scaricato con successo ({} byte).", raw_html.len());

            // ==========================================================
            // 4. PASSA L'HTML AL PARSER / ENGINE
            // Presumo che tu abbia una funzione nella tua libreria tipo:
            // let (clean_html, report) = nome_tua_crate::sanitizer::sanitize(&raw_html, &policy);
            // ==========================================================

            // Per ora facciamo un esempio simulando la chiamata al tuo parser:
            let clean_html = raw_html; // Sostituisci qui con la chiamata al tuo parser/engine reale!

            Json(SanitizeReport {
                status: "completed".to_string(),
                original_url: payload.url,
                sanitized_html: clean_html,
                message: "HTML elaborato ed esaminato dal motore di sanitizzazione!".to_string(),
            })
        }
        Err(e) => {
            println!("❌ Errore durante il fetching: {}", e);
            Json(SanitizeReport {
                status: "failed".to_string(),
                original_url: payload.url,
                sanitized_html: "".to_string(),
                message: format!("Errore di recupero della risorsa: {}", e),
            })
        }
    }
}

