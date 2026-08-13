use std::time::Duration;
use WebSanitizer::config::loader::default_policy;
use WebSanitizer::input::url::UrlFetcher;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::TagAllowListRule;
use mockito::Server;

// TEST DOWNLOAD URL & PIPELINE: HTML Malevolo scaricato da Server Mock
#[tokio::test]
async fn test_url_download_and_sanitization_success() {
    // Avviamo un Mock Server HTTP in memoria
    let mut server = Server::new_async().await;

    // Prepariamo la risposta del mock server con HTML infetto
    let raw_html = "<html><body><script>alert('xss')</script><h1>Contenuto Sicuro</h1></body></html>";
    let mock = server
        .mock("GET", "/page.html")
        .with_status(200)
        .with_header("content-type", "text/html")
        .with_body(raw_html)
        .create_async()
        .await;

    let target_url = format!("{}/page.html", server.url());

    // Creiamo l'UrlFetcher (max 1MB, depth 1, max 5 req, timeout 3s)
    let fetcher = UrlFetcher::new(1_000_000, 1, 5, Duration::from_secs(3))
        .expect("Inizializzazione UrlFetcher fallita");

    //  Scarichiamo l'HTML dalla rete simulata
    let download_result = fetcher.fetch(&target_url, 0).await;
    assert!(download_result.is_ok(), "Il download dell'URL dovrebbe avere successo");
    let html_content = download_result.unwrap();

    //  Passiamo l'HTML scaricato alla pipeline di sanitizzazione
    let policy = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));

    let mut parser = HtmlParser::new(&html_content);
    let dom = parser.parse().unwrap();
    let (sanitized_dom, actions) = engine.run(dom);

    let sanitized_html: String = sanitized_dom.iter().map(|n| n.to_html_string()).collect();

    assert!(!sanitized_html.contains("<script>"), "Il tag script scaricato da rete doveva essere rimosso");
    assert!(sanitized_html.contains("<h1>Contenuto Sicuro</h1>"));
    assert!(!actions.is_empty());

    mock.assert_async().await;
}


// TEST GESTIONE ERRORI DI RETE: HTTP 404, 500 e URL Malformati
#[tokio::test]
async fn test_url_fetch_network_errors_handling() {
    let mut server = Server::new_async().await;

    // A) Mock per Risposta HTTP 404 (Not Found)
    let mock_404 = server
        .mock("GET", "/not_found.html")
        .with_status(404)
        .create_async()
        .await;

    // B) Mock per Risposta HTTP 500 (Internal Server Error)
    let mock_500 = server
        .mock("GET", "/server_error.html")
        .with_status(500)
        .create_async()
        .await;

    let fetcher = UrlFetcher::new(1_000_000, 1, 5, Duration::from_secs(3)).unwrap();

    // TEST per 404 
    let url_404 = format!("{}/not_found.html", server.url());
    let res_404 = fetcher.fetch(&url_404, 0).await;
    assert!(res_404.is_err(), "Una risposta 404 deve restituire Err(...)");
    
    let err_msg_404 = res_404.unwrap_err().to_string();
    assert!(err_msg_404.contains("404") || err_msg_404.contains("status code"), "L'errore deve riflettere lo status 404");

    // TEST per 500 
    let url_500 = format!("{}/server_error.html", server.url());
    let res_500 = fetcher.fetch(&url_500, 0).await;
    assert!(res_500.is_err(), "Una risposta 500 deve restituire Err(...)");

    // TEST per URL INVALIDO/IRRAGGIUNGIBILE 
    let invalid_url = "http://127.0.0.1:1/porta_chiusa";
    let res_invalid = fetcher.fetch(invalid_url, 0).await;
    assert!(res_invalid.is_err(), "Un URL irraggiungibile deve fallire in modo controllato senza panico");

    mock_404.assert_async().await;
    mock_500.assert_async().await;
}