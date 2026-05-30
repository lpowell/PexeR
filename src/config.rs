use toml::Table;
use std::collections::HashMap;

use crate::YARA;

pub struct Config {
    pub rules: Option<HashMap<String, String>>,
    pub vt: Option<String>,
    pub yara: Option<YARA::YaraConfig>,
}

impl Config {
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let table: Table = toml_str.parse()?;
        let rules = table.get("Rules").and_then(|r| r.as_table()).map(|t| {
            t.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect()
        });
        let vt = table.get("vt").and_then(|v| v.as_str()).map(|s| s.to_string());
        let yara = table.get("YARA").and_then(|y| y.as_table()).map(|t| {
            let rules = t.get("rules").and_then(|r| r.as_array()).map(|arr| {
                arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
            });
            YARA::YaraConfig { rules }
        });
        Ok(Config { rules, vt, yara })
    }
}

