pub mod report;

// Esporta le strutture dati affinché siano accessibili come:
// crate::report::SanitizationReport
// crate::report::SanitizationAction
pub use report::{SanitizationReport, SanitizationAction};