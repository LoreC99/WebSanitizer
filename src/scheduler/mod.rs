pub mod workers;

use std::collections::HashSet;
use std::sync::atomic::AtomicU32;
use std::sync::RwLock;
use crate::report::SanitizationReport;

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