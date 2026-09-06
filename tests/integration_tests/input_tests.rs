use std::time::Duration;
use WebSanitizer::config::loader::default_policy;
use WebSanitizer::input::url::UrlFetcher;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::TagAllowListRule;
use WebSanitizer::sanitizer::resource_rules::ResourceGuard;
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

    let mut res_policy = default_policy().resources;
    res_policy.fetch_resources = true;

    // Creiamo il ResourceGuard con i limiti desiderati (max_depth: 1, max_requests: 5, max_bytes: 1MB)
    let guard = ResourceGuard::new(res_policy, 1, 5, 1_000_000);
    let fetcher = UrlFetcher::new(guard, Duration::from_secs(3))
        .expect("Inizializzazione UrlFetcher fallita");

    //Scarichiamo i byte dalla rete simulata
    let download_result = fetcher.fetch(&target_url, 0).await;
    assert!(download_result.is_ok(), "Il download dell'URL dovrebbe avere successo");
    let downloaded_bytes = download_result.unwrap();
    
    //Convertiamo i byte in stringa UTF-8
    let html_content = String::from_utf8_lossy(&downloaded_bytes).to_string();

    //Passiamo l'HTML scaricato alla pipeline di sanitizzazione
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

    let mut res_policy = default_policy().resources;
    res_policy.fetch_resources = true;

    let guard = ResourceGuard::new(res_policy, 1, 5, 1_000_000);
    let fetcher = UrlFetcher::new(guard, Duration::from_secs(3)).unwrap();

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

// TEST INTEGRATION: Interruzione download se il file supera il limite max_bytes (DoS Prevention)
#[tokio::test]
async fn test_url_fetch_large_resource_limit_integration() {
    // Avviamo il Mock Server HTTP
    let mut server = Server::new_async().await;

    // Prepariamo una risposta corposa (es. 500 byte di contenuto)
    let large_body = "A".repeat(500);

    let mock = server
        .mock("GET", "/large_file.html")
        .with_status(200)
        .with_header("content-type", "text/html")
        .with_body(large_body)
        .create_async()
        .await;

    let target_url = format!("{}/large_file.html", server.url());

    let mut res_policy = default_policy().resources;
    res_policy.fetch_resources = true;

    // Creiamo UrlFetcher imponendo un limite MAX di soli 100 byte
    let max_bytes_allowed = 100;
    let guard = ResourceGuard::new(res_policy, 1, 5, max_bytes_allowed);
    let fetcher = UrlFetcher::new(guard, Duration::from_secs(3))
        .expect("Inizializzazione UrlFetcher fallita");

    // Tentiamo il download
    let result = fetcher.fetch(&target_url, 0).await;

    // Verifichiamo che il download sia stato BLOCCATO con errore DoS
    assert!(result.is_err(), "Il download doveva fallire perché supera max_bytes");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("limite di byte") || err_msg.contains("DoS"),
        "L'errore deve indicare il blocco di sicurezza DoS, ricevuto invece: {}",
        err_msg
    );

    mock.assert_async().await;
}