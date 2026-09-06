use std::sync::Arc;
use std::sync::mpsc;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::fs;
use std::path::Path;

// Importiamo le strutture
use WebSanitizer::cli::cli::Cli;
use WebSanitizer::config::{default_policy, load_policy};
use WebSanitizer::scheduler::workers::{Job, SharedState, ThreadPool};
use WebSanitizer::input::directory::DirectoryScanner;
use WebSanitizer::report::report::BatchReport;
use WebSanitizer::utils::utils::{print_active_config, save_batch_report, save_sanitized_html};

fn main() {
    // 1. Parsing automatico degli argomenti da riga di comando
    let cli = Cli::parse_args();

    let inputs = cli.inputs.clone();

    println!("⚡ Avvio Web Sanitizer CLI...");
    print_active_config(&cli);
    println!("-> Trovati {} argomenti input da elaborare.", inputs.len());

    // Prepariamo la directory di output se non esiste
    if let Err(e) = fs::create_dir_all(&cli.output_dir) {
        eprintln!("Errore nella creazione della cartella di output: {}", e);
        std::process::exit(1);
    }

    // Leggiamo il TOML qui una sola volta per capire quali file cercare nelle directory
    let active_policy = match &cli.policy_path {
        Some(path) => load_policy(path).unwrap_or_else(|_| default_policy()),
        None => default_policy(),
    };
    let allowed_extensions = active_policy.directories.allowed_extensions.clone();

    // 2. Inizializzazione dello Stato Condiviso e dei Canali
    let shared_state = Arc::new(SharedState::new(HashSet::new()));
    let (result_sender, result_receiver) = mpsc::channel();

    // 3. Configurazione del numero di thread dinamico
    let num_threads = cli.threads.unwrap_or_else(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    });
    println!("-> Avvio pool con {} thread worker.\n", num_threads);

    // Condividiamo la configurazione CLI (in sola lettura) tra tutti i worker
    let cli_config = Arc::new(cli);

    // 4. Creazione del ThreadPool
    let pool = ThreadPool::new(
        num_threads,
        Arc::clone(&shared_state),
        result_sender,
        Arc::clone(&cli_config)
    );

    // 5. Distribuzione del Lavoro (Astrazione Input)
    let mut total_jobs = 0;

    for target in inputs {
        // Se ho un URL lo categorizzo come tale
        if target.starts_with("http://") || target.starts_with("https://") {
            pool.execute(Job::Url(target));
            total_jobs += 1;
        } else {
        // Altrimenti prendo il percorso del target e controllo se è un file o una directory
            let path = Path::new(&target);

            if path.is_file() {
                pool.execute(Job::File(target));
                total_jobs += 1;
            } else if path.is_dir() {
                // Gestisco qui il caso directory per passare immediatamente i file ai workers
                println!("Rilevata directory locale: {}. Scansione in corso...", target);

                let scanner = DirectoryScanner::new(
                    allowed_extensions.clone(),
                    cli_config.dir_max_depth,
                    cli_config.dir_max_files
                );

                match scanner.scan(path) {
                    Ok(safe_files) => {
                        for f in safe_files {
                            if let Some(path_str) = f.to_str() {
                                pool.execute(Job::File(path_str.to_string()));
                                total_jobs += 1;
                            }
                        }
                    }
                    Err(e) => eprintln!("Errore nella scansione della directory: {}", e),
                }
            } else {
                // In caso l'input non sia valido ritorno un errore
                eprintln!("Attenzione: L'input '{}' non è né un URL valido né un percorso locale esistente.", target);
            }
        }
    }
    drop(pool); // Permette la chiusura pulita una volta svuotata la coda

    // 6. Raccolta dei risultati
    let mut success_count = 0;
    let mut error_count = 0;
    let mut all_reports = Vec::new();

    println!("================ REPORT IN TEMPO REALE ================");
    for _ in 0..total_jobs {
        if let Ok(result) = result_receiver.recv() {
            if let Some(error) = result.error {
                println!("FALLITO: {} -> {}", result.target, error);
                error_count += 1;
            } else if let Some(report) = result.report {
                println!("COMPLETATO: {} -> (Minacce rimosse: {})", result.target, report.actions.len());
                success_count += 1;

                save_sanitized_html(&cli_config.output_dir, &result.target, &report.sanitized_html);
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

    // 8. Salvataggio del Report JSON Globale
    let batch_report = BatchReport {
        total_processed,
        total_threats_removed: total_threats,
        success_count,
        error_count,
        detailed_results: all_reports,
    };

    save_batch_report(&cli_config.report_file, &batch_report);
}