use std::path::Path;
use std::process;
use WebSanitizer::config;
use std::time::Duration;
use WebSanitizer::cli::cli::Cli;
use WebSanitizer::input::directory::DirectoryScanner;
use WebSanitizer::input::url::UrlFetcher;

#[tokio::main]
async fn main() {
    let args= Cli::parse_args();
    println!("Avvio web sanitizer con input: {:?}", args.inputs);

    println!("=== Avvio Web Sanitizer ===\n");

    // 2. Carichiamo la policy
    let policy = match args.policy_path {
        Some(path) => {
            println!("Tentativo di caricamento policy da: {:?}", path);
            // Usiamo un match per gestire elegantemente gli errori (es. file non trovato)
            match config::load_policy(&path) {
                Ok(p) => {
                    println!("Policy personalizzata caricata con successo!");
                    p
                }
                Err(e) => {
                    eprintln!("ERRORE FATALE: Impossibile leggere il file di policy.");
                    eprintln!("Dettagli errore: {}", e);
                    // Usciamo dal programma con codice di errore 1 (come richiesto dalle specifiche PDF)
                    process::exit(1);
                }
            }
        }
        None => {
            println!("Nessuna policy specificata. Utilizzo della policy di DEFAULT (Strict).");
            config::default_policy()
        }
    };

    // 3. Stampiamo la policy a video per verificare che i dati siano corretti!
    // L'operatore {:#?} stampa la struct formattata su più righe.
    println!("\nPolicy attiva:\n{:#?}", policy);

    // 4. (Futuro) Qui passeremo la `policy` e `args.inputs` al Thread Pool / Scheduler
    // ...

    // println!("=== Test del modulo DirectoryScanner ===");
    //
    // // 1. Inizializziamo lo scanner con le nostre regole di sicurezza
    // let allowed_ext = vec!["html".to_string(), "htm".to_string()];
    // let scanner = DirectoryScanner::new(
    //     allowed_ext,
    //     2,  // max_depth: scendiamo al massimo di 2 livelli
    //     5,  // max_files: fermiamoci dopo aver trovato 5 file
    // );
    //
    // // 2. Puntiamo alla cartella di test che hai creato
    // let mut vec_test = args.inputs;
    // let path = vec_test.pop().unwrap();
    // let test_dir = Path::new(&path);
    // println!("Inizio scansione della cartella: {}", test_dir.display());
    //
    // // 3. Eseguiamo la scansione e gestiamo il risultato
    // match scanner.scan(test_dir) {
    //     Ok(files) => {
    //         println!("✅ Scansione completata con successo!");
    //         println!("Trovati {} file HTML validi:", files.len());
    //
    //         // Stampiamo l'elenco dei percorsi trovati
    //         for (index, file_path) in files.iter().enumerate() {
    //             println!("  {}. {}", index + 1, file_path.display());
    //         }
    //     }
    //     Err(e) => {
    //         eprintln!("❌ Errore critico durante la scansione: {}", e);
    //     }
    // }

    // println!("=== Test del modulo UrlFetcher ===");
    //
    // // 1. Inizializziamo il fetcher con limiti stringenti (es. 1MB max, 5 sec timeout)
    // let fetcher = match UrlFetcher::new(
    //     args.max_bytes,              // max_bytes: 1 MB
    //     2,                      // max_depth: 2
    //     3,                     // max_request: 3
    //     Duration::from_secs(args.timeout_seconds), // timeout
    // ) {
    //     Ok(f) => f,
    //     Err(e) => {
    //         eprintln!("Errore nell'inizializzazione del client: {}", e);
    //         return;
    //     }
    // };
    //
    // // 2. Facciamo il test su una pagina reale
    // let mut vec_test_url = args.inputs;
    // let url = vec_test_url.pop().unwrap();
    // let test_url = url.as_str();
    // println!("Tentativo di download di: {}", test_url);
    //
    // // 3. Chiamiamo fetch passando l'URL e profondità iniziale 0
    // match fetcher.fetch(test_url, 0).await {
    //     Ok(html) => {
    //         println!("Download completato con successo!");
    //         println!("Dimensione file: {} byte", html.len());
    //         println!("--- Primi 250 caratteri ---");
    //         println!("{:.250}", html);
    //     }
    //     Err(e) => {
    //         eprintln!("Errore durante il download: {}", e);
    //     }
    // }
    //
    // // 4. Test max_request
    // // for i in 1..=5 {
    // //     println!("\nTentativo n°{}", i);
    // //     match fetcher.fetch(test_url, 0).await {
    // //         Ok(_) => println!("✅ Successo: richiesta {} andata a buon fine.", i),
    // //         Err(e) => println!("❌ Bloccata: {}", e),
    // //     }
    // // }
    //
    // // 5. Test max_depth
    // // Test a profondità 0 (Simuliamo la pagina principale)
    // println!("\n[Depth 0] Tento il download della pagina principale...");
    // match fetcher.fetch(test_url, 0).await {
    //     Ok(_) => println!("✅ Successo: pagina principale scaricata."),
    //     Err(e) => println!("❌ Fallito: {}", e),
    // }
    //
    // // Test a profondità 1 (Simuliamo un file CSS trovato nella pagina)
    // println!("\n[Depth 1] Tento il download di un CSS fittizio...");
    // match fetcher.fetch(test_url, 1).await {
    //     Ok(_) => println!("✅ Successo: risorsa di livello 1 scaricata."),
    //     Err(e) => println!("❌ Fallito: {}", e),
    // }
    //
    // // Test a profondità 3 (Simuliamo un font importato dal CSS, che supera il limite)
    // println!("\n[Depth 3] Tento il download oltre il limite consentito...");
    // match fetcher.fetch(test_url, 3).await {
    //     Ok(_) => println!("❌ Errore critico: il limite non ha funzionato, ha scaricato il file!"),
    //     Err(e) => println!("✅ Test Superato: la richiesta è stata bloccata. Motivo: {}", e),
    // }
}
