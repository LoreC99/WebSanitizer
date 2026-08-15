use std::sync::atomic::{Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::runtime::Builder;
use crate::cli::cli::Cli;
// ==========================================
// IMPORTAZIONI DAL CORE DEL SANITIZER
// ==========================================
use crate::config::loader;
use crate::input::url::UrlFetcher;
use crate::sanitizer::resource_rules::{MimeSniffer};
use crate::input::file::FileReader;
pub use crate::scheduler::{Job, JobResult, SharedState};
use crate::utils::utils::{evaluate_mime_type, process_css, process_html};

// ==========================================
// IL THREAD POOL E I WORKER
// ==========================================

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl ThreadPool {
    pub fn new(
        size: usize,
        shared_state: Arc<SharedState>,
        result_sender: mpsc::Sender<JobResult>,
        config: Arc<Cli>
    ) -> ThreadPool {
        assert!(size > 0);
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(
                id,
                Arc::clone(&receiver),
                Arc::clone(&shared_state),
                result_sender.clone(),
                Arc::clone(&config),
            ));
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    pub fn execute(&self, job: Job) {
        if let Some(sender) = &self.sender {
            sender.send(job).unwrap();
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        drop(self.sender.take());
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

impl Worker {
    fn new(
        id: usize,
        receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
        state: Arc<SharedState>,
        result_sender: mpsc::Sender<JobResult>,
        config: Arc<Cli>,
    ) -> Worker {
        let thread = thread::spawn(move || {
            let rt = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Impossibile creare il runtime Tokio per il worker");

            let policy = match &config.policy_path {
                Some(path) => {
                    match loader::load_policy(path) {
                        Ok(custom_policy) => {
                            println!("Worker {} utilizza la policy personalizzata: {:?}", id, path);
                            custom_policy
                        },
                        Err(e) => {
                            eprintln!("⚠️ Worker {}: Errore nel caricare la policy {:?} ({}). Fallback a default.", id, path, e);
                            loader::default_policy()
                        }
                    }
                },
                None => {
                    loader::default_policy()
                }
            };

            loop {
                let message = receiver.lock().unwrap().recv();

                match message {
                    Ok(job) => {
                        let target_name = match &job {
                            Job::Url(u) => u.clone(),
                            Job::File(f) => f.clone(),
                        };

                        println!("Worker {} sta analizzando: {}", id, target_name);

                        let job_result = rt.block_on(async {

                            // 1. ASTRAZIONE DELL'INPUT: Rete o File Locale?
                            let fetch_result = match job {
                                Job::Url(url) => {
                                    // IL FETCH DI RETE USA GIÀ CORRETTAMENTE UrlFetcher
                                    let fetcher = match UrlFetcher::new(
                                        config.max_bytes,
                                        config.max_depth,
                                        config.max_requests,
                                        std::time::Duration::from_secs(config.timeout_seconds),
                                    ) {
                                        Ok(f) => f,
                                        Err(e) => {
                                            return JobResult {
                                                target: target_name.clone(),
                                                report: None,
                                                error: Some(format!("Errore Inizializzazione Fetcher: {}", e)),
                                            };
                                        }
                                    };

                                    fetcher.fetch(&url, 0).await.map_err(|e| format!("Errore Rete: {}", e))
                                },
                                Job::File(filepath) => {
                                    // ========================================================
                                    // Utilizzo di FileReader al posto di std::fs
                                    // ========================================================
                                    let reader = FileReader::new(config.max_bytes);

                                    reader.read(std::path::Path::new(&filepath))
                                        .await
                                        .map_err(|e| format!("Errore Lettura File (DoS Prevention): {}", e))
                                }
                            };
                            match fetch_result {
                                Ok(raw_bytes_vec) => {
                                    let raw_bytes = raw_bytes_vec.as_slice();

                                    // Sniffiamo i byte PURI, così il GZIP verrà finalmente riconosciuto!
                                    let detected_type = MimeSniffer::sniff(raw_bytes);

                                    // 1. Valutazione tipi binari o pericolosi
                                    if let Some(binary_result) = evaluate_mime_type(&detected_type, raw_bytes, &target_name) {
                                        return binary_result;
                                    }

                                    // 2. Se siamo arrivati qui, è sicuro. ORA possiamo convertirlo in stringa.
                                    let raw_content = String::from_utf8_lossy(raw_bytes).to_string();

                                    // 3. Valutazione CSS
                                    let is_css = target_name.contains("/css/") || target_name.ends_with(".css");
                                    if is_css {
                                        return process_css(&raw_content, &target_name);
                                    }

                                    // 4. Valutazione HTML (Default)
                                    process_html(&raw_content, &target_name, &policy)
                                }
                                Err(e) => {
                                    JobResult {
                                        target: target_name.clone(),
                                        report: None,
                                        error: Some(e),
                                    }
                                }
                            }
                        });
                        // Aggiornamento Thread-Safe delle statistiche condivise
                        state.total_processed.fetch_add(1, Ordering::Relaxed);
                        if let Some(report) = &job_result.report {
                            let actions_count = report.actions.len() as u32;
                            if actions_count > 0 {
                                state.threats_removed.fetch_add(actions_count, Ordering::Relaxed);
                            }
                        }

                        // Invio del risultato al main thread
                        result_sender.send(job_result).unwrap();
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}