use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpListener;

// ==========================================
// IMPORTAZIONI DALLA LIBRERIA
// ==========================================
use WebSanitizer::config::loader;
use WebSanitizer::input::url::UrlFetcher;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::{DangerousAttributeRule, TagAllowListRule};

// ==========================================
// STRUTTURE PER I DATI (JSON)
// ==========================================

#[derive(Deserialize)]
pub struct SanitizeRequest {
    pub url: String,
}

#[derive(Serialize)]
pub struct SanitizeReport {
    pub status: String,
    pub original_url: String,
    pub sanitized_html: String,
    pub message: String,
}

// ==========================================
// IL MOTORE DEL SERVER (PUNTO DI INGRESSO)
// ==========================================

#[tokio::main]
async fn main() {
    // Creiamo il router per intercettare le richieste POST
    let app = Router::new().route("/v1/resources", post(process_resource));

    // Ci mettiamo in ascolto sulla porta 3000
    let listener = TcpListener::bind("0.0.0.0:3000").await.expect("Impossibile aprire la porta 3000");

    println!("🚀 Web Sanitizer in ascolto su http://localhost:3000");
    println!("In attesa di richieste da evil-origin...\n");

    // Avviamo il loop del server
    axum::serve(listener, app).await.unwrap();
}

// ==========================================
// LOGICA DI GESTIONE DELLA RICHIESTA
// ==========================================

async fn process_resource(Json(payload): Json<SanitizeRequest>) -> Json<SanitizeReport> {
    println!("⚡ RICEVUTA RICHIESTA!");
    println!("-> Target: {}", payload.url);

    // 1. Carichiamo la policy di default
    let policy = loader::default_policy();

    // 2. Inizializziamo il Fetcher per scaricare l'URL
    let fetcher = match UrlFetcher::new(
        policy.resources.max_resource_size,
        policy.resources.max_depth,
        10,
        Duration::from_secs(5),
    ) {
        Ok(f) => f,
        Err(e) => {
            return Json(SanitizeReport {
                status: "error".to_string(),
                original_url: payload.url.clone(),
                sanitized_html: "".to_string(),
                message: format!("Impossibile creare il fetcher: {}", e),
            });
        }
    };

    // 3. Scarichiamo l'HTML
    // Nota: Se la url punta a localhost:3100, assicurati di aver
    // temporaneamente disattivato il blocco SSRF in `url.rs`!
    match fetcher.fetch(&payload.url, 0).await {
        Ok(raw_html) => {
            println!("-> HTML scaricato con successo ({} byte). Avvio Parser...", raw_html.len());

            // Rimuoviamo il tag doctype che confonde il nostro parser custom
            let clean_raw_html = raw_html
                .replace("<!doctype html>", "")
                .replace("<!DOCTYPE html>", "")
                .replace("<!DOCTYPE HTML>", "");

            // AGGIUNGI QUESTA RIGA PER VEDERE IL CODICE SORGENTE:
            println!("-> CONTENUTO:\n{}\n-------------------", clean_raw_html);

            // 4. PARSING: String -> Vec<Node>
            let mut parser = HtmlParser::new(&clean_raw_html);
            match parser.parse() {
                Ok(dom) => {
                    println!("-> Parsing completato. Avvio Sanitizer Engine...");

                    // 5. ENGINE: Pulizia del DOM
                    let mut engine = SanitizerEngine::new();

                    // Inizializziamo la tua regola passandole la porzione 'html' della policy.
                    // Usiamo clone() per evitare problemi di ownership, supponendo che
                    // policy.html contenga l'oggetto HtmlPolicy.
                    let rule = TagAllowListRule {
                        config: policy.html.clone(),
                    };

                    // Inizializziamo la regola passando la sezione URL della policy
                    let rule2 = DangerousAttributeRule {
                        url_config: policy.url.clone(), // Usa .clone() per passare una copia della configurazione
                    };

                    // Aggiungiamo le regole inscatolate (Box) al motore
                    engine.add_rule(Box::new(rule));

                    engine.add_rule(Box::new(rule2));

                    let (clean_dom, report_actions) = engine.run(dom);

                    // 6. RENDERING: Vec<Node> -> String
                    let mut clean_html_string = String::new();
                    for node in clean_dom {
                        clean_html_string.push_str(&node.to_html_string());
                    }

                    println!("-> Pulizia completata! Trovate {} minacce.", report_actions.len());

                    Json(SanitizeReport {
                        status: "success".to_string(),
                        original_url: payload.url,
                        sanitized_html: clean_html_string,
                        message: format!("Pulizia eseguita. Azioni: {}", report_actions.len()),
                    })
                },
                Err(e) => {
                    Json(SanitizeReport {
                        status: "error".to_string(),
                        original_url: payload.url,
                        sanitized_html: "".to_string(),
                        message: format!("Errore di parsing HTML: {:?}", e),
                    })
                }
            }
        }
        Err(e) => {
            Json(SanitizeReport {
                status: "error".to_string(),
                original_url: payload.url,
                sanitized_html: "".to_string(),
                message: format!("Errore di rete: {}", e),
            })
        }
    }
}