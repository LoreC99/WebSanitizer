use WebSanitizer::config::loader::default_policy;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::{DangerousAttributeRule, MetaRefreshRule, TagAllowListRule};

#[test]
fn test_full_pipeline_multi_threat_sanitization() {
    // 1. HTML infetto con minacce multiple
    let raw_html = r#"
        <!DOCTYPE html>
        <html>
            <head>
                <script>alert('xss');</script>
            </head>
            <body>
                <h1 onclick="alert('click')">Titolo</h1>
                <a href="javascript:alert('link')">Link Malizioso</a>
            </body>
        </html>
    "#;

    // 2. Creiamo l'engine registrando le regole di sicurezza HTML
    let policy = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));
    engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));

    // 3. Parsiamo l'HTML grezzo in un albero DOM di nodi
    let mut parser = HtmlParser::new(raw_html);
    let dom = parser.parse().expect("Parsing dell'HTML fallito");

    // 4. Eseguiamo il motore di sanitizzazione sul DOM
    let (sanitized_dom, report) = engine.run(dom);

    // 5. Ricostruiamo la stringa HTML sanificata dai nodi
    let sanitized_html: String = sanitized_dom
        .iter()
        .map(|n| n.to_html_string())
        .collect();

    // 6. VERIFICHE:
    // A) Il report deve contenere le azioni di sanitizzazione eseguite
    assert!(!report.is_empty(), "Il report non dovrebbe essere vuoto per HTML infetto");

    // B) L'HTML sanificato non deve più contenere i frammenti malevoli
    assert!(!sanitized_html.contains("<script>"), "Il tag <script> doveva essere rimosso");
    assert!(!sanitized_html.contains("onclick"), "L'attributo onclick doveva essere rimosso");
    assert!(!sanitized_html.contains("javascript:"), "Lo pseudo-protocollo javascript: doveva essere rimosso");

    // C) Il contenuto legittimo deve essere mantenuto
    assert!(sanitized_html.contains("Titolo"), "Il testo del titolo deve essere presente");
    assert!(sanitized_html.contains("Link Malizioso"), "Il testo del link deve essere presente");
}


#[test]
fn test_full_pipeline_multi_threat_metarefresh_sanitization() {
    // 1. HTML infetto con il meta refresh da bloccare e un div pulito
    let raw_html = r#"
        <html>
            <body>
                <meta http-equiv="refresh" content="0;url=http://evil.com">
                <div>Titolo Legittimo</div>
            </body>
        </html>
    "#;

    // 2. Creiamo l'engine registrando le regole di sicurezza HTML
    let config = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(MetaRefreshRule { config: config.html.clone() }));

    // 3. Parsiamo l'HTML grezzo in un albero DOM di nodi
    let mut parser = HtmlParser::new(raw_html);
    let dom = parser.parse().expect("Parsing dell'HTML fallito");

    // 4. Eseguiamo il motore di sanitizzazione sul DOM
    let (sanitized_dom, report) = engine.run(dom);

    // 5. Ricostruiamo la stringa HTML sanificata dai nodi
    let sanitized_html: String = sanitized_dom
        .iter()
        .map(|n| n.to_html_string())
        .collect();

    // 6. VERIFICHE:
    // Il report deve contenere le azioni di sanitizzazione eseguite
    assert!(!report.is_empty(), "Il report non dovrebbe essere vuoto per meta refresh infetto");

    // Controlla che non contenga più l'attributo http-equiv="refresh":
    assert!(!sanitized_html.contains("http-equiv"), "Gli attributi di refresh avrebbero dovuto essere rimossi");

    // Il contenuto legittimo deve essere mantenuto
    assert!(sanitized_html.contains("Titolo"), "Il testo del titolo deve essere presente");

}

#[test]
fn test_full_pipeline_multi_threat_iframe_sanitization(){
    // 1. HTML infetto contenente un iframe pericoloso e del testo legittimo
    let raw_html = r#"
        <html>
            <body>
                <iframe src="http://evil.com/malware.html"></iframe>
                <p>Contenuto Testuale Sicuro</p>
            </body>
        </html>
    "#;

    let config = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule { config: config.html.clone() }));

     // 3. Parsiamo l'HTML grezzo in un albero DOM di nodi
    let mut parser = HtmlParser::new(raw_html);
    let dom = parser.parse().expect("Parsing dell'HTML fallito");

    // 4. Eseguiamo il motore di sanitizzazione sul DOM
    let (sanitized_dom, report) = engine.run(dom);

    // 5. Ricostruiamo la stringa HTML sanificata dai nodi
    let sanitized_html: String = sanitized_dom
        .iter()
        .map(|n| n.to_html_string())
        .collect();

    // 6. VERIFICHE:
    //Il report deve contenere le azioni di sanitizzazione eseguite
    assert!(!report.is_empty(), "Il report non dovrebbe essere vuoto per HTML infetto");

    // L'HTML sanificato non deve più contenere i frammenti malevoli
    assert!(!sanitized_html.contains("<iframe>"), "Il tag <iframe> doveva essere rimosso");

    // Il contenuto legittimo deve essere mantenuto
    assert!(sanitized_html.contains("Contenuto Testuale Sicuro"), "Il testo del link deve essere presente");


}