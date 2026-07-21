use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;

// ==========================================
// 1. STATO CONDIVISO (Shared State)
// ==========================================

/// Contiene i dati che devono essere letti/scritti da più thread contemporaneamente.
pub struct SharedState {
    /// Cache degli URL già risolti per evitare di scaricare due volte la stessa risorsa.
    /// Usiamo RwLock perché ci saranno moltissime letture (per controllare se un URL è in cache)
    /// e poche scritture (solo quando si scopre un URL nuovo).
    pub resolved_urls: RwLock<HashSet<String>>,

    /// Block-list per lookups veloci.
    /// Usiamo RwLock (o potremmo usare nulla se fosse 100% read-only dopo il caricamento),
    /// ma RwLock permette di aggiornare la block-list a caldo se necessario.
    pub block_list: RwLock<HashSet<String>>,

    /// Statistiche globali.
    /// Usiamo Atomics perché sono la primitiva più veloce e a costo quasi zero
    /// per incrementare semplici contatori da thread diversi senza bloccare tutto con un Mutex.
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

/// Rappresenta un singolo lavoro da eseguire (es. un file da leggere o un URL da scaricare).
pub enum Job {
    Url(String),
    File(String),
}

/// Il risultato finale che il worker spedisce indietro al thread principale.
pub struct JobResult {
    pub target: String,
    pub sanitized_content: Option<String>,
    pub error: Option<String>,
}

// ==========================================
// 3. IL THREAD POOL E I WORKER
// ==========================================

pub struct ThreadPool {
    workers: Vec<Worker>,
    // Il canale per spedire i lavori. Opzionale perché ci serve poterlo "droppare" in chiusura.
    sender: Option<mpsc::Sender<Job>>,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl ThreadPool {
    /// Crea un nuovo ThreadPool con `size` thread.
    pub fn new(
        size: usize,
        shared_state: Arc<SharedState>,
        result_sender: mpsc::Sender<JobResult>
    ) -> ThreadPool {
        assert!(size > 0);

        // Canale MPSC (Multi-Producer, Single-Consumer) per la coda dei task
        let (sender, receiver) = mpsc::channel();

        // Trasformiamo il receiver in Arc<Mutex<Receiver>>.
        // Arc serve per condividere la proprietà tra i thread.
        // Mutex garantisce che solo un worker alla volta possa estrarre un lavoro dalla coda.
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(
                id,
                Arc::clone(&receiver),
                Arc::clone(&shared_state),
                result_sender.clone(),
            ));
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    /// Invia un nuovo lavoro alla coda
    pub fn execute(&self, job: Job) {
        if let Some(sender) = &self.sender {
            sender.send(job).unwrap();
        }
    }
}

/// Implementiamo Drop per spegnere i thread in modo pulito alla fine del programma
impl Drop for ThreadPool {
    fn drop(&mut self) {
        println!("Chiusura del canale di invio per far terminare i worker...");
        drop(self.sender.take());

        for worker in &mut self.workers {
            println!("Spegnimento del worker {}", worker.id);
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
    ) -> Worker {
        let thread = thread::spawn(move || {
            loop {
                // 1. Acquisiamo il lock sulla coda per prelevare il prossimo task
                let message = receiver.lock().unwrap().recv();

                match message {
                    Ok(job) => {
                        println!("Worker {} ha ricevuto un lavoro.", id);

                        // Incrementiamo la statistica dei file elaborati in modo thread-safe
                        state.total_processed.fetch_add(1, Ordering::Relaxed);

                        // ====================================================
                        // QUI ANDRA' LA VERA LOGICA DI SANITIZZAZIONE
                        // Esempio:
                        // let result = match job {
                        //     Job::Url(u) => /* scarica e pulisci */,
                        //     Job::File(f) => /* leggi file e pulisci */,
                        // };
                        // ====================================================

                        // Inviamo il risultato finto indietro al main thread
                        let target_name = match job {
                            Job::Url(u) => u,
                            Job::File(f) => f,
                        };

                        let fake_result = JobResult {
                            target: target_name,
                            sanitized_content: Some("<html>Pulito!</html>".to_string()),
                            error: None,
                        };

                        result_sender.send(fake_result).unwrap();
                    }
                    Err(_) => {
                        // Il canale è stato chiuso (il ThreadPool è stato distrutto).
                        // Usciamo dal loop e terminiamo il thread.
                        println!("Worker {} si sta spegnendo (coda disconnessa).", id);
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