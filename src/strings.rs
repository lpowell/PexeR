use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use regex::Regex;

// pub struct
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: StringEncoding,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

// public functions
pub fn extract_strings(buffer: &[u8]) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset: usize = 0;

    for (i, &byte) in buffer.iter().enumerate() {
        if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= 4 {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(ExtractedString {
                        value: s,
                        offset: start_offset as u64,
                        encoding: StringEncoding::Ascii,
                    });
                }
            }
            current_string.clear();
        }
    }

    if current_string.len() >= 4 {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.push(ExtractedString {
                value: s,
                offset: start_offset as u64,
                encoding: StringEncoding::Ascii,
            });
        }
    }

    strings
}

pub fn notable_strings<'a>(strings: &'a Vec<ExtractedString>, patterns: &'a HashMap<String, String>) -> HashMap<&'a str, Vec<&'a ExtractedString>> {

    // let mut results: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut results: HashMap<&'a str, Vec<&'a ExtractedString>> = HashMap::new();

    

    for (name, rule) in patterns {
        let regex = Regex::new(rule).unwrap();
        let matches: Vec<&ExtractedString> = strings
            .iter()
            .filter(|s| regex.is_match(&s.value))
            .collect();

        if !matches.is_empty() {
            results.insert(name.as_str(), matches);
        }
    }

    results

}