use std::time::Duration;
use WebSanitizer::cli::cli::Cli;
use WebSanitizer::input::url::UrlFetcher;

#[tokio::main]
async fn main() {
    let args= Cli::parse_args();
    println!("Avvio web sanitizer con input: {:?}", args.inputs);

    println!("=== Test del modulo UrlFetcher ===");

    // 1. Inizializziamo il fetcher con limiti stringenti (es. 1MB max, 5 sec timeout)
    let fetcher = match UrlFetcher::new(
        1_048_576,              // max_bytes: 1 MB
        2,                      // max_depth: 3
        3,                     // max_request: 10
        Duration::from_secs(5), // timeout
    ) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Errore nell'inizializzazione del client: {}", e);
            return;
        }
    };

    // 2. Facciamo il test su una pagina reale
    let mut vec_test_url = args.inputs;
    let url = vec_test_url.pop().unwrap();
    let test_url = url.as_str();
    println!("Tentativo di download di: {}", test_url);

    // 3. Chiamiamo fetch passando l'URL e profondità iniziale 0
    match fetcher.fetch(test_url, 0).await {
        Ok(html) => {
            println!("Download completato con successo!");
            println!("Dimensione file: {} byte", html.len());
            println!("--- Primi 250 caratteri ---");
            println!("{:.250}", html);
        }
        Err(e) => {
            eprintln!("Errore durante il download: {}", e);
        }
    }

    // 4. Test max_request
    // for i in 1..=5 {
    //     println!("\nTentativo n°{}", i);
    //     match fetcher.fetch(test_url, 0).await {
    //         Ok(_) => println!("✅ Successo: richiesta {} andata a buon fine.", i),
    //         Err(e) => println!("❌ Bloccata: {}", e),
    //     }
    // }

    // 5. Test max_depth
    // Test a profondità 0 (Simuliamo la pagina principale)
    println!("\n[Depth 0] Tento il download della pagina principale...");
    match fetcher.fetch(test_url, 0).await {
        Ok(_) => println!("✅ Successo: pagina principale scaricata."),
        Err(e) => println!("❌ Fallito: {}", e),
    }

    // Test a profondità 1 (Simuliamo un file CSS trovato nella pagina)
    println!("\n[Depth 1] Tento il download di un CSS fittizio...");
    match fetcher.fetch(test_url, 1).await {
        Ok(_) => println!("✅ Successo: risorsa di livello 1 scaricata."),
        Err(e) => println!("❌ Fallito: {}", e),
    }

    // Test a profondità 3 (Simuliamo un font importato dal CSS, che supera il limite)
    println!("\n[Depth 3] Tento il download oltre il limite consentito...");
    match fetcher.fetch(test_url, 3).await {
        Ok(_) => println!("❌ Errore critico: il limite non ha funzionato, ha scaricato il file!"),
        Err(e) => println!("✅ Test Superato: la richiesta è stata bloccata. Motivo: {}", e),
    }
}
