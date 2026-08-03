use std::fs;
use std::path::PathBuf;
use WebSanitizer::config::loader::default_policy;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::{DangerousAttributeRule, TagAllowListRule};
use WebSanitizer::report::report::SanitizationReport;
use serde_json::Value;

fn temp_path(filename: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("websanitizer_test_{}", filename));
    p
}

#[test]
//File Locale HTML → Output Sanitizzato → Report JSON
fn test_integration_file_to_output_and_json_report() {
    let input_file = temp_path("input_infetto.html");
    let output_file = temp_path("output_pulito.html");
    let report_file = temp_path("report_finale.json");

    let raw_html = r#"
        <!DOCTYPE html>
        <html>
            <head>
                <script>alert('xss');</script>
            </head>
            <body>
                <h1 onclick="alert('click')">Titolo Progetto</h1>
                <a href="javascript:alert('link')">Link Pericoloso</a>
            </body>
        </html>
    "#;

    fs::write(&input_file, raw_html).expect("Scrittura input fallita");

    let content = fs::read_to_string(&input_file).expect("Lettura input fallita");

    let policy = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));
    engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));

    let mut parser = HtmlParser::new(&content);
    let dom = parser.parse().expect("Parsing DOM fallito");
    let (sanitized_dom, actions) = engine.run(dom);

    let sanitized_html: String = sanitized_dom
        .iter()
        .map(|n| n.to_html_string())
        .collect();

    fs::write(&output_file, &sanitized_html).expect("Scrittura HTML sanificato fallita");

    // Crezione del report strutturato con i tipi definiti nel progetto
    let report = SanitizationReport {
        input_source: input_file.to_string_lossy().to_string(),
        status: "Cleaned".to_string(),
        actions,
        sanitized_html: sanitized_html.clone(),
    };

    let json_report = serde_json::to_string_pretty(&report).expect("Serializzazione JSON fallita");
    fs::write(&report_file, json_report).expect("Scrittura JSON fallita");

    // Verifiche
    assert!(output_file.exists());
    let saved_html = fs::read_to_string(&output_file).unwrap();
    assert!(!saved_html.contains("<script>"));
    assert!(!saved_html.contains("onclick"));
    assert!(!saved_html.contains("javascript:"));
    assert!(saved_html.contains("Titolo Progetto"));

    assert!(report_file.exists());
    let saved_json_str = fs::read_to_string(&report_file).unwrap();
    let json_val: Value = serde_json::from_str(&saved_json_str).unwrap();

    let json_actions = json_val.get("actions").and_then(|v| v.as_array()).unwrap();
    assert_eq!(json_actions.len(), 3);

    // Cleanup
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(output_file);
    let _ = fs::remove_file(report_file);
}