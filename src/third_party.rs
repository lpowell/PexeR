use std::collections::hash_map;
use std::collections::HashMap;
use reqwest::blocking::Client;
use serde_json;
use chrono::{DateTime, Utc};


// this should be async, but that is a pain to do
// also I don't care

// https://docs.virustotal.com/reference/file-info
pub fn vt_fetch(key: &str, hash: &str) -> HashMap<String, String> {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&url)
        .header("x-apikey", key)
        .header("accept", "application/json")
        .send().unwrap()
        .text().unwrap();
    let mut attributes = serde_json::from_str::<serde_json::Value>(&response).unwrap();
    attributes = attributes.get("data").and_then(|d| d.get("attributes")).unwrap().clone();
    let mut results: HashMap<String, String> = HashMap::new();
    results.insert("Type Description".to_string(), attributes.get("type_description").unwrap().to_string());
    results.insert("Meaningful Name".to_string(), attributes.get("meaningful_name").unwrap().to_string());
    results.insert("First Submission".to_string(), DateTime::from_timestamp(attributes.get("first_submission_date").unwrap().as_i64().unwrap(), 0).unwrap().format("%Y-%m-%d %H:%M:%S").to_string());
    results.insert("Creation".to_string(), attributes.get("creation_date").unwrap().to_string());
    results.insert("Tags".to_string(), attributes.get("tags").unwrap().to_string());
    results.insert("Type Tags".to_string(), attributes.get("type_tags").unwrap().to_string());
    results.insert("Submitted".to_string(), attributes.get("times_submitted").unwrap().to_string());
    results.insert("Votes".to_string(), attributes.get("total_votes").unwrap().to_string());
    results.insert("Last Analysis Stats".to_string(), attributes.get("last_analysis_stats").unwrap().to_string());
    results.insert("Names".to_string(), attributes.get("names").unwrap().to_string());

    results
}


