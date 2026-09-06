use std::fs;
use std::path::PathBuf;
use WebSanitizer::config::loader::{default_policy, load_policy};
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::TagAllowListRule;

fn temp_config_path(filename: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("websanitizer_config_test_{}", filename));
    p
}

//TEST POLICY CUSTOM: La pipeline applica la policy caricata da TOML
#[test]
fn test_custom_policy_applied_to_pipeline() {
    let custom_config_path = temp_config_path("custom_permissive.toml");

    let custom_toml = r#"
        [html]
        allow_scripts = false
        remove_iframes = true
        block_meta_refresh = true
        allowed_tags = ["html", "head", "body", "p"]

        [url]
        allowed_schemes = ["http", "https"]
        block_data_uris = true
        block_javascript_uris = true

        [resources]
        fetch_resources = false
        max_depth = 1
        max_resource_size = 1000

        [directories]
        allowed_extensions = ["html", "css"]
    "#;

    fs::write(&custom_config_path, custom_toml).expect("Impossibile scrivere il TOML custom");

    let policy_result = load_policy(&custom_config_path);
    assert!(policy_result.is_ok(), "La policy custom dovrebbe essere caricata con successo");
    let custom_policy = policy_result.unwrap();

    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule {
        config: custom_policy.html.clone(),
    }));

    let raw_html = "<html><body><h1>Titolo Vietato</h1><p>Testo Ammesso</p></body></html>";
    let mut parser = HtmlParser::new(raw_html);
    let dom = parser.parse().unwrap();

    let (sanitized_dom, report) = engine.run(dom);
    let sanitized_html: String = sanitized_dom.iter().map(|n| n.to_html_string()).collect();

    assert!(!sanitized_html.contains("<h1>"), "<h1> avrebbe dovuto essere rimosso secondo la policy custom");
    assert!(sanitized_html.contains("<p>Testo Ammesso</p>"), "<p> doveva essere conservato");
    assert!(!report.is_empty());

    let _ = fs::remove_file(custom_config_path);
}

//TEST GESTIONE ERRORE: File Inesistente -> Fallback a Default Policy
#[test]
fn test_policy_file_not_found_fallback_to_default() {
    let non_existent_path = "percorso/inventato/inesistente_policy.toml";
    let policy_result = load_policy(non_existent_path);
    // Deve restituire un Result::Err (senza fare panic)
    assert!(policy_result.is_err(), "Il caricamento di un file inesistente deve restituire Err");
    // Gestione del fallback: se il caricamento fallisce, usiamo la policy di default
    let active_policy = policy_result.unwrap_or_else(|err| {
        println!("Errore caricamento config ({}), attivo fallback a default policy", err);
        default_policy()
    });
    
    assert_eq!(active_policy.html.allow_scripts, false);
    assert_eq!(active_policy.html.remove_iframes, true);
}

// TEST GESTIONE ERRORE: TOML Malformato 
#[test]
fn test_policy_malformed_toml_handling() {
    let bad_config_path = temp_config_path("malformed_policy.toml");
    // TOML con sintassi invalida (manca la chiusura delle parentesi e tipi errati)
    let bad_toml = r#"
        [html
        allow_scripts = "stringa_invalida_invece_di_bool"
    "#;
    fs::write(&bad_config_path, bad_toml).expect("Impossibile creare il file TOML malformato");
    let policy_result = load_policy(&bad_config_path);

    assert!(policy_result.is_err(), "Un TOML sintatticamente errato deve fallire con Err");
    // Cleanup
    let _ = fs::remove_file(bad_config_path);
}