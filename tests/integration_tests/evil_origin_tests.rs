use std::time::Duration;
use std::path::PathBuf;
use std::fs;
use WebSanitizer::config::loader::default_policy;
use WebSanitizer::input::directory::DirectoryScanner;
use WebSanitizer::input::url::UrlFetcher;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::TagAllowListRule;
use WebSanitizer::sanitizer::resource_rules::ResourceGuard;

// TEST: Scansione dei test nella cartella corpus_test (benigni + malevoli) e stampa valutazioni esplicite
#[test]
fn test_corpus_local_evaluation() {
    let mut corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    corpus_path.push("corpus_test");

    if !corpus_path.exists() {
        println!("Cartella corpus_test non trovata");
        return;
    }

    let scanner = DirectoryScanner::new(vec!["html".to_string(), "css".to_string()], 5, 100);
    let files = scanner.scan(&corpus_path).expect("Scansione corpus fallita");

    assert!(!files.is_empty(), "Il corpus_test deve contenere file di test");

    let policy = default_policy();

    let mut total_benign = 0;
    let mut false_positives = 0;

    let mut total_malicious = 0;
    let mut detected_malicious = 0;

    for file_path in files {
        let content = fs::read_to_string(&file_path).unwrap();
        let path_str = file_path.to_string_lossy().to_string();

        if path_str.contains("benign") {
            total_benign += 1;
            if path_str.ends_with(".html") {
                let job_res = WebSanitizer::utils::utils::process_html(&content, &path_str, &policy);
                if job_res.error.is_some() {
                    false_positives += 1;
                }
                assert!(job_res.error.is_none(), "Il file benigno non deve generare errori");
            } else if path_str.ends_with(".css") {
                let job_res = WebSanitizer::utils::utils::process_css(&content, &path_str);
                if job_res.error.is_some() {
                    false_positives += 1;
                }
                assert!(job_res.error.is_none(), "Il CSS benigno non deve generare errori");
            }
        } else if path_str.contains("malicious") {
            total_malicious += 1;
            if path_str.ends_with(".html") {
                let job_res = WebSanitizer::utils::utils::process_html(&content, &path_str, &policy);
                assert!(job_res.error.is_none(), "Il file malevolo deve essere gestito senza errori");
                if let Some(report) = job_res.report {
                    let is_clean = !report.sanitized_html.contains("<script>")
                        && !report.sanitized_html.contains("onclick=")
                        && !report.sanitized_html.contains("javascript:");
                    if is_clean || report.status == "Cleaned" || report.status == "Clean" {
                        detected_malicious += 1;
                    }
                    assert!(!report.sanitized_html.contains("<script>"), "Tag script malevoli neutralizzati");
                    assert!(!report.sanitized_html.contains("onclick="), "Handler onclick neutralizzato");
                    assert!(!report.sanitized_html.contains("javascript:"), "URI javascript: neutralizzati");
                }
            } else if path_str.ends_with(".css") {
                let job_res = WebSanitizer::utils::utils::process_css(&content, &path_str);
                if let Some(report) = job_res.report {
                    let is_clean = !report.sanitized_html.contains("expression(")
                        && !report.sanitized_html.contains("javascript:");
                    if is_clean || report.status == "Cleaned" || report.status == "Clean" {
                        detected_malicious += 1;
                    }
                    assert!(!report.sanitized_html.contains("expression("), "CSS expression neutralizzata");
                    assert!(!report.sanitized_html.contains("javascript:"), "CSS javascript URL neutralizzato");
                }
            }
        }
    }

    let fp_rate = if total_benign > 0 { (false_positives as f64 / total_benign as f64) * 100.0 } else { 0.0 };
    let dr_rate = if total_malicious > 0 { (detected_malicious as f64 / total_malicious as f64) * 100.0 } else { 0.0 };

    println!("\n==================================================");
    println!("WebSanitizer - Valutazione del Corpus di Test");
    println!("==================================================");
    println!("Analisi {} file benigni...", total_benign);
    println!("[RESULT] False Positive Rate (Falsi Positivi): {}/{} ({:.1}%)", false_positives, total_benign, fp_rate);
    println!("Analisi {} file malevoli...", total_malicious);
    println!("[RESULT] Detection Rate su Corpus Malevolo: {}/{} ({:.1}%)", detected_malicious, total_malicious, dr_rate);
    println!("==================================================\n");
}

// TEST: prova la connessione al server Docker evil-origin (se attivo su localhost:3100)
#[tokio::test]
async fn test_evil_origin_docker_integration() {
    let target_url = "http://localhost:3100/health";

    let mut res_policy = default_policy().resources;
    res_policy.fetch_resources = true;

    let guard = ResourceGuard::new(res_policy, 1, 5, 1_000_000);
    let fetcher = UrlFetcher::new(guard, Duration::from_secs(2)).expect("Inizializzazione UrlFetcher fallita");
    let res = fetcher.fetch(target_url, 0).await;

    match res {
        Ok(bytes) => {
            let body = String::from_utf8_lossy(&bytes).to_string();
            println!("Connesso a evil-origin Docker server: {}", body);
            assert!(body.contains("evil-origin") || body.contains("ok"), "Risposta health check valida");

            // Testiamo un endpoint di minaccia reale da evil-origin
            let threat_url = "http://localhost:3100/html/script-tag";
            if let Ok(threat_bytes) = fetcher.fetch(threat_url, 0).await {
                let raw_html = String::from_utf8_lossy(&threat_bytes).to_string();
                
                let policy = default_policy();
                let mut engine = SanitizerEngine::new();
                engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));

                let mut parser = HtmlParser::new(&raw_html);
                if let Ok(dom) = parser.parse() {
                    let (sanitized_dom, actions) = engine.run(dom);
                    let clean_html: String = sanitized_dom.iter().map(|n| n.to_html_string()).collect();

                    assert!(!clean_html.contains("<script>"), "Il tag script da evil-origin deve essere eliminato");
                    
                    assert!(!actions.is_empty(), "La sanitizzazione deve registrare azioni per evil-origin");
                }
            }
        }
        Err(_) => {
            println!("Server evil-origin Docker non attivo su http://localhost:3100 (test integrato saltato delicatamente).");
        }
    }
}
