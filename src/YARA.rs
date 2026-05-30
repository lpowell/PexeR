use yara_x::{Compiler, Rules};
use crate::config::Config;
use serde::Deserialize;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Deserialize, Debug, Default)]
pub struct YaraConfig {
    pub rules: Option<Vec<String>>,
}

pub fn compile_rules(config: &YaraConfig) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();

    let paths = match &config.rules {
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
}
fn load_file(compiler: &mut yara_x::Compiler, path: &std::path::Path) -> Result<(), String> {
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|_| format!("Failed to read YARA rule: {}", path.display()));

    compiler
        .add_source(src.as_str())
        .unwrap();

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