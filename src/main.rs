use std::sync::Arc;
use std::sync::mpsc;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::fs;
use std::path::Path;
// Importiamo le tue strutture
use WebSanitizer::cli::cli::Cli;
use WebSanitizer::scheduler::workers::{Job, SharedState, ThreadPool};
use serde::Serialize;
use WebSanitizer::report::SanitizationReport;
use WebSanitizer::utils::utils::explore_directory;

#[derive(Serialize)]
pub struct BatchReport {
    pub total_processed: u32,
    pub total_threats_removed: u32,
    pub success_count: u32,
    pub error_count: u32,
    pub detailed_results: Vec<SanitizationReport>,
}

fn main() {
    // 1. Parsing automatico degli argomenti da riga di comando
    let cli = Cli::parse_args();

    let inputs = cli.inputs.clone();
    let num_jobs = inputs.len();

    println!("⚡ Avvio Web Sanitizer CLI...");
    println!("-> Trovati {} target da elaborare in batch.", num_jobs);

    // Prepariamo la directory di output se non esiste
    if let Err(e) = fs::create_dir_all(&cli.output_dir) {
        eprintln!("❌ Errore nella creazione della cartella di output: {}", e);
        std::process::exit(1);
    }

    // 2. Inizializzazione dello Stato Condiviso e dei Canali
    let shared_state = Arc::new(SharedState::new(HashSet::new()));
    let (result_sender, result_receiver) = mpsc::channel();

    // 3. Configurazione del numero di thread dinamico
    // Se l'utente non passa -t, usiamo i core logici disponibili della CPU (fallback a 4)
    let num_threads = cli.threads.unwrap_or_else(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    });
    println!("-> Avvio pool con {} thread worker.\n", num_threads);

    // Condividiamo la configurazione CLI (in sola lettura) tra tutti i worker
    let cli_config = Arc::new(cli);

    // 4. Creazione del ThreadPool (passiamo anche cli_config)
    let pool = ThreadPool::new(
        num_threads,
        Arc::clone(&shared_state),
        result_sender,
        Arc::clone(&cli_config)
    );

    // 5. Distribuzione del Lavoro (Astrazione Input)
    for target in inputs {
        if target.starts_with("http://") || target.starts_with("https://") {
            // È chiaramente un URL di rete
            pool.execute(Job::Url(target));
        } else {
            // Trattiamolo come percorso locale
            let path = Path::new(&target);

            if path.is_file() {
                pool.execute(Job::File(target));
            } else if path.is_dir() {
                println!("📂 Rilevata directory locale: {}. Scansione in corso...", target);
                explore_directory(path, &pool);
            } else {
                eprintln!("⚠️ Attenzione: L'input '{}' non è né un URL valido né un percorso locale esistente.", target);
            }
        }
    }
    drop(pool); // Permette la chiusura pulita una volta svuotata la coda

    // 6. Raccolta dei risultati
    let mut success_count = 0;
    let mut error_count = 0;
    let mut all_reports = Vec::new();

    println!("================ REPORT IN TEMPO REALE ================");
    for _ in 0..num_jobs {
        if let Ok(result) = result_receiver.recv() {
            if let Some(error) = result.error {
                println!("❌ FALLITO: {} -> {}", result.target, error);
                error_count += 1;
            } else if let Some(report) = result.report {
                println!("✅ COMPLETATO: {} -> (Minacce rimosse: {})",
                         result.target, report.actions.len());
                success_count += 1;

                // ========================================================
                // NUOVO: SALVATAGGIO DEL FILE HTML SANITIZZATO
                // ========================================================

                // 1. Creiamo un nome file sicuro a partire dall'URL
                let safe_filename = result.target.replace(&['/', ':', '\\', '?', '&', '=', '#'][..], "_");

                // 2. Uniamo il percorso della cartella di output con il nuovo nome
                let file_path = cli_config.output_dir.join(format!("{}.html", safe_filename));

                // 3. Scriviamo il contenuto pulito su disco
                if let Err(e) = fs::write(&file_path, &report.sanitized_html) {
                    eprintln!("   ⚠️ Errore nel salvare il file HTML per {}: {}", result.target, e);
                } else {
                    println!("   -> Contenuto pulito salvato in: {:?}", file_path);
                }

                // ========================================================

                all_reports.push(report);
            }
        }
    }
    println!("=======================================================");

    // 7. Statistiche Globali
    let total_processed = shared_state.total_processed.load(Ordering::Relaxed);
    let total_threats = shared_state.threats_removed.load(Ordering::Relaxed);

    println!("\n📊 STATISTICHE BATCH FINALI:");
    println!("   - Target elaborati con successo: {}", success_count);
    println!("   - Target falliti: {}", error_count);
    println!("   - Minacce totali rimosse: {}\n", total_threats);

    // ==========================================
    // 8. SALVATAGGIO DEL REPORT JSON GLOBALE
    // ==========================================
    let batch_report = BatchReport {
        total_processed,
        total_threats_removed: total_threats,
        success_count,
        error_count,
        detailed_results: all_reports,
    };

    // Serializziamo in formato JSON leggibile ("pretty")
    match serde_json::to_string_pretty(&batch_report) {
        Ok(json_string) => {
            // Scriviamo sul disco al percorso specificato dalla CLI (es. --report-file)
            if let Err(e) = fs::write(&cli_config.report_file, json_string) {
                eprintln!("❌ Errore durante il salvataggio del report su disco: {}", e);
            } else {
                println!("📄 Report JSON globale salvato con successo in: {:?}", cli_config.report_file);
            }
        },
        Err(e) => eprintln!("❌ Errore durante la serializzazione del report JSON: {}", e),
    }
}