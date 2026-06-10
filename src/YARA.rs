use yara_x::{Compiler, Rules};
use crate::{config::Config, strings};
use serde::Deserialize;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Deserialize, Debug, Default)]
pub struct YaraConfig {
    pub rules: Option<Vec<String>>,
}


// this overflows when you attempt to load large repos in main
// sending to a new thread with a 32mb stack size
// this should be enough for most use cases. I could try and dynamically size this based on the number of rules if it keeps causing issues.
pub fn compile_rules(config: &YaraConfig) -> Result<yara_x::Rules, String> {

    let paths: Option<Vec<String>> = config.rules.clone();
    std::thread::Builder::new()
        .name("PexeR-rule-compiler".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn( move || -> Result<yara_x::Rules, String> {
            let mut compiler = yara_x::Compiler::new();

                let paths = match paths {
                    Some(p) => p,
                    None => return Ok(compiler.build()),
                };

                for raw_path in paths {
                    let path = PathBuf::from(raw_path);
                    if path.is_file() {
                        load_file(&mut compiler, &path)?;
                    } else if path.is_dir() {
                        for entry in walkdir::WalkDir::new(path)
                            .into_iter()
                            .filter_map(|e| e.ok())
                            .filter(|e| {
                                e.path()
                                    .extension()
                                    .map(|ext| ext == "yar" || ext == "yara")
                                    .unwrap_or(false)
                            })
                        {
                            load_file(&mut compiler, entry.path())?;
                        }
                    } else {
                        return Err(format!("YARA path does not exist: {}", path.display()));
                    }
                }

                // println!("Loaded Paths: {:#?}", paths);
                Ok(compiler.build())
        })
        .map_err(|e| format!("Failed to spawn thread: {}", e)).unwrap()
        .join()
        .map_err(|_| "YARA compiler thread panicked".to_string())
        .unwrap()
   
}
fn load_file(compiler: &mut yara_x::Compiler, path: &std::path::Path) -> Result<(), String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        eprintln!("loading: {}", path.display());

    compiler
        .add_source(src.as_str())
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    Ok(())
}

pub fn scan(rules: &yara_x::Rules, data: &[u8]) -> Result<Vec<String>, String> {
    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan(data).unwrap();

    let matched = results
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect();

    Ok(matched)
}