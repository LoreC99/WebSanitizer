use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use tokio::runtime::Builder;
use crate::cli::cli::Cli;
// ==========================================
// IMPORTAZIONI DAL CORE DEL SANITIZER
// ==========================================
use crate::config::loader;
use crate::input::url::UrlFetcher;
use crate::parser::html::HtmlParser;
use crate::sanitizer::engine::SanitizerEngine;
use crate::sanitizer::html_rules::{DangerousAttributeRule, IdnHomographRule, MetaRefreshRule, SsrfAttributeRule, TagAllowListRule};
use crate::report::{SanitizationAction, SanitizationReport};
use crate::sanitizer::resource_rules::{CssSanitizer, MimeSniffer, DetectedType, ImageValidator, PdfValidator};
use crate::sanitizer::url_rules::UrlValidator;
// ==========================================
// 1. STATO CONDIVISO (Shared State)
// ==========================================

pub struct SharedState {
    pub resolved_urls: RwLock<HashSet<String>>,
    pub block_list: RwLock<HashSet<String>>,
    pub total_processed: AtomicU32,
    pub threats_removed: AtomicU32,
}

impl SharedState {
    pub fn new(initial_block_list: HashSet<String>) -> Self {
        Self {
            resolved_urls: RwLock::new(HashSet::new()),
            block_list: RwLock::new(initial_block_list),
            total_processed: AtomicU32::new(0),
            threats_removed: AtomicU32::new(0),
        }
    }
}

// ==========================================
// 2. DEFINIZIONE DEL TASK E DEL REPORT
// ==========================================

pub enum Job {
    Url(String),
    File(String),
}

pub struct JobResult {
    pub target: String,
    pub report: Option<SanitizationReport>,
    pub error: Option<String>,
}

// ==========================================
// 3. IL THREAD POOL E I WORKER
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
        config: Arc<Cli>, // <--- 3. RICEVUTO QUI DAL WORKER
    ) -> Worker {
        let thread = thread::spawn(move || {
            // Dato che usiamo la keyword "move", l'Arc<Cli> di nome "config"
            // viene spostato all'interno del thread e ora può essere usato!

            // 1. Creazione del Runtime Tokio
            let rt = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Impossibile creare il runtime Tokio per il worker");

            // Carichiamo la policy: se l'utente ha passato un file usiamo quello, altrimenti fallback al default
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
                    // Nessun file passato da terminale, usiamo la policy integrata
                    loader::default_policy()
                }
            };

            loop {
                let message = receiver.lock().unwrap().recv();

                match message {
                    Ok(job) => {
                        // Estraiamo il nome del target
                        let target_name = match &job {
                            Job::Url(u) => u.clone(),
                            Job::File(f) => f.clone(),
                        };

                        println!("Worker {} sta analizzando: {}", id, target_name);

                        // Esecuzione bloccante del motore asincrono all'interno del worker
                        let job_result = rt.block_on(async {

                            // 1. ASTRAZIONE DELL'INPUT: Rete o File Locale?
                            let fetch_result = match job {
                                Job::Url(url) => {
                                    // ========================================================
                                    // NUOVO: VALIDAZIONE PREVENTIVA DELL'URL INIZIALE
                                    // ========================================================
                                    if let Err(reason) = UrlValidator::is_safe_redirect_hop(&url) {
                                        return JobResult {
                                            target: target_name.clone(),
                                            report: None,
                                            error: Some(format!("URL bloccato preventivamente: {}", reason)),
                                        };
                                    }

                                    // Inizializziamo il fetcher solo se ci serve la rete
                                    let fetcher = match UrlFetcher::new(
                                        config.max_bytes,
                                        config.max_depth,
                                        config.max_requests,
                                        std::time::Duration::from_secs(config.timeout_seconds),
                                    ) {
                                        Ok(f) => f,
                                        Err(e) => {
                                            // Restituiamo direttamente JobResult invece di Err()
                                            return JobResult {
                                                target: target_name.clone(),
                                                report: None,
                                                error: Some(format!("Errore Inizializzazione Fetcher: {}", e)),
                                            };
                                        }
                                    };

                                    // Chiamata asincrona di rete
                                    fetcher.fetch(&url, 0).await.map_err(|e| format!("Errore Rete: {}", e))
                                },
                                Job::File(filepath) => {
                                    // Lettura sincrona/locale dal file system (senza limiti di rete applicati qui)
                                    std::fs::read_to_string(&filepath).map_err(|e| format!("Errore Lettura File: {}", e))
                                }
                            };

                            // 2. ANALISI DEL CONTENUTO SCARICATO/LETTO
                            match fetch_result {
                                Ok(raw_content) => {
                                    let raw_bytes = raw_content.as_bytes();
                                    let detected_type = MimeSniffer::sniff(raw_bytes);

                                    let mut is_css = false;
                                    let mut is_html = false;

                                    match detected_type {
                                        DetectedType::Html => { is_html = true; },
                                        DetectedType::Png => {
                                            // =======================================================
                                            // CONTROLLO: VALIDAZIONE DIMENSIONI PNG (DIMENSION BOMB)
                                            // =======================================================
                                            if let Err(reason) = ImageValidator::check_png_dimensions(raw_bytes) {
                                                return JobResult {
                                                    target: target_name.clone(),
                                                    report: None,
                                                    error: Some(reason),
                                                };
                                            }

                                            let report = SanitizationReport {
                                                input_source: target_name.clone(),
                                                status: "Clean".to_string(),
                                                actions: vec![],
                                                sanitized_html: "PNG Image (Placeholder)".to_string(),
                                            };
                                            return JobResult { target: target_name.clone(), report: Some(report), error: None };
                                        },
                                        DetectedType::Pdf => {
                                            // =======================================================
                                            // IMPLEMENTAZIONE: "lopdf mode" (Stripping)
                                            // =======================================================
                                            return match PdfValidator::sanitize_pdf(raw_bytes) {
                                                Ok((_sanitized_pdf_bytes, report_actions)) => {
                                                    let status = if report_actions.is_empty() {
                                                        "Clean".to_string()
                                                    } else {
                                                        "Cleaned".to_string()
                                                    };

                                                    // Decidiamo il testo prima di "consumare" (move) lo status
                                                    let html_placeholder = if status == "Clean" {
                                                        "PDF Document (Placeholder)".to_string()
                                                    } else {
                                                        "PDF Document (Sanitized: Active Content Stripped)".to_string()
                                                    };

                                                    let report = SanitizationReport {
                                                        input_source: target_name.clone(),
                                                        status, // Qui status viene "spostato" dentro la struct in modo sicuro
                                                        actions: report_actions,
                                                        sanitized_html: html_placeholder,
                                                    };

                                                    return JobResult { target: target_name.clone(), report: Some(report), error: None };
                                                },
                                                Err(e) => {
                                                    // Se il PDF è malformato (es. l'attaccante ha creato un PDF falso per confondere il parser)
                                                    JobResult {
                                                        target: target_name.clone(),
                                                        report: None,
                                                        error: Some(e),
                                                    }
                                                }
                                            }
                                        },
                                        DetectedType::Unknown => {
                                            if target_name.contains("/css/") || target_name.ends_with(".css") {
                                                is_css = true;
                                            } else {
                                                is_html = true;
                                            }
                                        }
                                    }

                                    if is_css {
                                        let sanitized_css = CssSanitizer::sanitize(&raw_content);
                                        let mut report_actions = Vec::new();
                                        if sanitized_css != raw_content {
                                            report_actions.push(SanitizationAction {
                                                rule_fired: "MALICIOUS_CSS_SANITIZED".to_string(),
                                                location: "Stylesheet".to_string(),
                                                original_fragment: "Active CSS Vectors".to_string(),
                                                replacement: "Stripped".to_string(),
                                            });
                                        }
                                        let status = if report_actions.is_empty() { "Clean".to_string() } else { "Cleaned".to_string() };
                                        let report = SanitizationReport {
                                            input_source: target_name.clone(),
                                            status,
                                            actions: report_actions,
                                            sanitized_html: sanitized_css,
                                        };
                                        return JobResult { target: target_name.clone(), report: Some(report), error: None };
                                    }

                                    if is_html {
                                        let clean_raw_html = raw_content
                                            .replace("<!doctype html>", "")
                                            .replace("<!DOCTYPE html>", "")
                                            .replace("<!DOCTYPE HTML>", "");

                                        let mut parser = HtmlParser::new(&clean_raw_html);
                                        return match parser.parse() {
                                            Ok(dom) => {
                                                let mut engine = SanitizerEngine::new();
                                                let mut active_html_policy = policy.html.clone();

                                                if active_html_policy.remove_iframes {
                                                    active_html_policy.allowed_tags.retain(|tag| !["iframe", "object", "embed"].contains(&tag.as_str()));
                                                }
                                                if !active_html_policy.allow_scripts {
                                                    active_html_policy.allowed_tags.retain(|tag| tag != "script");
                                                }

                                                engine.add_rule(Box::new(TagAllowListRule { config: active_html_policy.clone() }));
                                                if active_html_policy.block_meta_refresh {
                                                    engine.add_rule(Box::new(MetaRefreshRule { config: active_html_policy }));
                                                }
                                                engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));
                                                engine.add_rule(Box::new(SsrfAttributeRule { config: policy.url.clone() }));
                                                engine.add_rule(Box::new(IdnHomographRule));

                                                let (clean_dom, report_actions) = engine.run(dom);
                                                let mut clean_html_string = String::new();
                                                for node in clean_dom {
                                                    clean_html_string.push_str(&node.to_html_string());
                                                }

                                                let status = if report_actions.is_empty() { "Clean".to_string() } else { "Cleaned".to_string() };
                                                let report = SanitizationReport {
                                                    input_source: target_name.clone(),
                                                    status,
                                                    actions: report_actions,
                                                    sanitized_html: clean_html_string,
                                                };
                                                JobResult { target: target_name.clone(), report: Some(report), error: None }
                                            },
                                            Err(e) => {
                                                JobResult {
                                                    target: target_name.clone(),
                                                    report: None,
                                                    error: Some(format!("Errore HTML Parser: {:?}", e)),
                                                }
                                            }
                                        }
                                    }

                                    JobResult {
                                        target: target_name.clone(),
                                        report: None,
                                        error: Some("Fallback non gestito raggiunto.".to_string()),
                                    }
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