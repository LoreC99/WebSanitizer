pub mod directory;
pub mod file;
pub mod url;

use std::path::PathBuf;

///// Enum che rappresenta le tre tipologie di input supportate
// pub enum InputSource {
//     File(PathBuf),
//     Directory(PathBuf),
//     Url(String)
// }
///// Analizza la stringa di input fornita dalla CLI e la classifica.
// pub fn classify_input_source(input_str: &str) -> InputSource {
//     // 1. Controllo se è un URL (inizia con http o https)
//     if input_str.starts_with("https://") || input_str.starts_with("http://") {
//         return InputSource::Url(input_str.to_string())
//     }

    // 2. Se non è un URL, lo trattiamo come un percorso del file system
    // let path = PathBuf::from(input_str);

    // Nota: path.is_dir() controlla fisicamente sul disco se la cartella esiste.
    // Se il percorso non esiste ancora, potresti voler gestire l'errore o
    // assumere che sia un file di default.
//    if path.is_dir() {
  //      InputSource::Directory(path)
    //} else {
     //   InputSource::File(path)
    //}
//}