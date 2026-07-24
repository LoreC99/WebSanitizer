use axum::{routing::post, Json, Router};
use tokio::net::TcpListener;

// ==========================================
// IMPORTAZIONI DALLA LIBRERIA
// ==========================================
use WebSanitizer::config::loader;
use WebSanitizer::input::url::UrlFetcher;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::{DangerousAttributeRule, IdnHomographRule, MetaRefreshRule, SsrfAttributeRule, TagAllowListRule};
use WebSanitizer::report::{SanitizationAction, SanitizationReport};
use WebSanitizer::report::report::SanitizationRequest;
// Aggiunti MimeSniffer e DetectedType
use WebSanitizer::sanitizer::resource_rules::{CssSanitizer, MimeSniffer, DetectedType};

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

pub async fn process_resource(Json(payload): Json<SanitizationRequest>) -> Json<SanitizationReport> {
    println!("⚡ RICEVUTA RICHIESTA!");
    println!("-> Target: {}", payload.url);

    // 1. Carichiamo la policy di default
    let policy = loader::default_policy();

    // 2. Inizializziamo il Fetcher per scaricare l'URL
    let fetcher = match UrlFetcher::new(
        policy.resources.max_resource_size,
        policy.resources.max_depth,
        10,
        std::time::Duration::from_secs(5),
    ) {
        Ok(f) => f,
        Err(e) => {
            return Json(SanitizationReport {
                input_source: payload.url,
                status: "Error".to_string(),
                actions: vec![SanitizationAction {
                    rule_fired: "INITIALIZATION_ERROR".to_string(),
                    location: "UrlFetcher".to_string(),
                    original_fragment: e.to_string(),
                    replacement: "Aborted".to_string(),
                }],
                sanitized_html: "".to_string(),
            });
        }
    };

    // 3. Scarichiamo il contenuto
    match fetcher.fetch(&payload.url, 0).await {
        Ok(raw_content) => {
            println!("-> Contenuto scaricato. Avvio MIME Sniffing...");

            let raw_bytes = raw_content.as_bytes();
            let detected_type = MimeSniffer::sniff(raw_bytes);

            let mut is_css = false;
            let mut is_html = false;

            // ==========================================
            // IL BIVIO DI ROUTING BASATO SUL VERO CONTENUTO
            // ==========================================
            match detected_type {
                DetectedType::Html => {
                    println!("-> [MIME] Rilevato HTML vero e proprio!");
                    is_html = true;
                },
                DetectedType::Png => {
                    println!("-> [MIME] Rilevata Immagine PNG vera e propria!");
                    // TODO: Implementeremo il PngSanitizer qui nei prossimi step
                    return Json(SanitizationReport {
                        input_source: payload.url,
                        status: "Clean".to_string(),
                        actions: vec![],
                        sanitized_html: "PNG Image (Placeholder)".to_string(),
                    });
                },
                DetectedType::Pdf => {
                    println!("-> [MIME] Rilevato PDF vero e proprio!");
                    // TODO: Implementeremo il PdfSanitizer qui nei prossimi step
                    return Json(SanitizationReport {
                        input_source: payload.url,
                        status: "Clean".to_string(),
                        actions: vec![],
                        sanitized_html: "PDF Document (Placeholder)".to_string(),
                    });
                },
                DetectedType::Unknown => {
                    // Fallback: Se non sappiamo cos'è, guardiamo l'URL
                    if payload.url.contains("/css/") || payload.url.ends_with(".css") {
                        println!("-> [MIME] Tipo sconosciuto, ma URL indica CSS.");
                        is_css = true;
                    } else {
                        println!("-> [MIME] Tipo sconosciuto. Fallback su HtmlParser per sicurezza...");
                        is_html = true;
                    }
                }
            }

            // ==========================================
            // ESECUZIONE DEL SANIFICATORE CSS
            // ==========================================
            if is_css {
                println!("-> Avvio CssSanitizer...");
                let sanitized_css = CssSanitizer::sanitize(&raw_content);

                let mut report_actions = Vec::new();
                if sanitized_css != raw_content {
                    report_actions.push(SanitizationAction {
                        rule_fired: "MALICIOUS_CSS_SANITIZED".to_string(),
                        location: "Stylesheet".to_string(),
                        original_fragment: "Active CSS Vectors".to_string(),
                        replacement: "Stripped".to_string(),
                    });
                }

                let status = if report_actions.is_empty() {
                    "Clean".to_string()
                } else {
                    "Cleaned".to_string()
                };

                return Json(SanitizationReport {
                    input_source: payload.url,
                    status,
                    actions: report_actions,
                    sanitized_html: sanitized_css,
                });
            }

            // ==========================================
            // ESECUZIONE DEL SANIFICATORE HTML
            // ==========================================
            if is_html {
                println!("-> Avvio HtmlParser...");
                let clean_raw_html = raw_content
                    .replace("<!doctype html>", "")
                    .replace("<!DOCTYPE html>", "")
                    .replace("<!DOCTYPE HTML>", "");

                // 4. PARSING: String -> Vec<Node>
                let mut parser = HtmlParser::new(&clean_raw_html);
                return match parser.parse() {
                    Ok(dom) => {
                        println!("-> Parsing completato. Avvio Sanitizer Engine...");

                        // 5. ENGINE: Pulizia del DOM
                        let mut engine = SanitizerEngine::new();

                        // --- APPLICAZIONE DINAMICA DELLE POLICY ---
                        let mut active_html_policy = policy.html.clone();

                        if active_html_policy.remove_iframes {
                            active_html_policy.allowed_tags.retain(|tag| !["iframe", "object", "embed"].contains(&tag.as_str()));
                        }

                        if !active_html_policy.allow_scripts {
                            active_html_policy.allowed_tags.retain(|tag| tag != "script");
                        }

                        engine.add_rule(Box::new(TagAllowListRule {
                            config: active_html_policy.clone(),
                        }));

                        if active_html_policy.block_meta_refresh {
                            engine.add_rule(Box::new(MetaRefreshRule {
                                config: active_html_policy,
                            }));
                        }

                        engine.add_rule(Box::new(DangerousAttributeRule {
                            url_config: policy.url.clone(),
                        }));

                        engine.add_rule(Box::new(SsrfAttributeRule {
                            config: policy.url.clone(),
                        }));

                        engine.add_rule(Box::new(IdnHomographRule));
                        // ------------------------------------------

                        let (clean_dom, report_actions) = engine.run(dom);

                        // 6. RENDERING: Vec<Node> -> String
                        let mut clean_html_string = String::new();
                        for node in clean_dom {
                            clean_html_string.push_str(&node.to_html_string());
                        }

                        // 7. DETERMINAZIONE DELLO STATO
                        let status = if report_actions.is_empty() {
                            "Clean".to_string()
                        } else {
                            "Cleaned".to_string()
                        };

                        println!("-> Pulizia completata! Trovate {} minacce.", report_actions.len());

                        Json(SanitizationReport {
                            input_source: payload.url,
                            status,
                            actions: report_actions,
                            sanitized_html: clean_html_string,
                        })
                    },
                    Err(e) => {
                        Json(SanitizationReport {
                            input_source: payload.url,
                            status: "Rejected".to_string(),
                            actions: vec![SanitizationAction {
                                rule_fired: "HTML_PARSER_ERROR".to_string(),
                                location: "Parser".to_string(),
                                original_fragment: format!("{:?}", e),
                                replacement: "Rejected".to_string(),
                            }],
                            sanitized_html: "".to_string(),
                        })
                    }
                }
            }

            // Fallback finale di sicurezza (non dovrebbe mai essere raggiunto)
            Json(SanitizationReport {
                input_source: payload.url,
                status: "Error".to_string(),
                actions: vec![],
                sanitized_html: "".to_string(),
            })
        }
        Err(e) => {
            // Errore di rete
            Json(SanitizationReport {
                input_source: payload.url,
                status: "Error".to_string(),
                actions: vec![SanitizationAction {
                    rule_fired: "NETWORK_ERROR".to_string(),
                    location: "Fetcher".to_string(),
                    original_fragment: e.to_string(),
                    replacement: "Aborted".to_string(),
                }],
                sanitized_html: "".to_string(),
            })
        }
    }
}