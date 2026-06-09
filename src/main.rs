use clap::Parser;
use clap::builder::Str;
use console::Term;
use console::style;
use indicatif::ProgressStyle;
use indicatif::ProgressBar;
use core::panic;
use std::{fs, path::Path};
use std::time::Duration;
use std::collections::HashMap;
use prettytable::{Table, Row, Cell};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use entropy::shannon_entropy;


// mods
mod config;
mod YARA;
mod strings;
mod pe_parser;
mod deep_scan;
mod third_party;
mod graph;
mod disassemble;


// private structs
#[derive(Parser, Debug)]
#[command(version, about, long_about = r"
The Portable Executable eXaminiation Engine (Rust)*, is a CLI tool for analyizing PE files. It pulls basic data and incorporates custom regex and YARA rules.
Future integrations will include VirusTotal, packer detection, an other integrations. 
", before_help = r"
 _____              _____
|  __ \            |  __ \
| |__) |____  _____| |__) |
|  ___/ _ \ \/ / _ \  _  /
| |  |  __/>  <  __/ | \ \
|_|   \___/_/\_\___|_|  \_\

*Name pending change
")]
struct Args {
    #[arg( help = "Path to PE. Required.", required=true, value_name = "FILE")]
    file: String,

    #[arg(short, long, default_value_t = false, help = "Lenient parsing mode - disables RVA resolution and uses permissive parsing. This may allow malformed PE files to be parsed. However, it can lead to data and display errors.")]
    lenient: bool,

    #[arg(short, long, default_value_t = false, help = "Deep scanning mode. This will enable packer detection, overlay analysis, and other more intensive scanning techniques.")]
    deep: bool,

    #[arg(short, long, default_value_t = false, help = "VirusTotal integration. Requires API key in config.toml. This will fetch and display VirusTotal data for the file hash.")]
    vt: bool,

    #[arg(short, long, default_value_t = false, help = "Graph relationships between PE files in a directory. Saves graph to graph.svg in the working directory. Very much a WIP.")]
    graph: bool,
    
    #[arg(short = 'D', long, default_value_t = false, help = "Graph relationships between PE files in a directory. Saves graph to graph.svg in the working directory. Very much a WIP.")]
    disassemble: bool,

    #[arg(short, long, default_value = "", help = "Graph relationships between PE files in a directory. Saves graph to graph.svg in the working directory. Very much a WIP.")]
    offset: String
}


// private functions
fn truncate_str(s: &str, limit: usize) -> String {
    if s.len() > limit {
        format!("{}...", &s[0..limit])
    } else {
        s.to_string()
    }
}

// prettytable


// spinners
fn spinner(msg: &str) -> ProgressBar {
    let spinner_style = ProgressStyle::with_template("{spinner} {msg}")
        .unwrap()
        .tick_strings(&["⣾", "⣷", "⣯", "⣟", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⣻", "⣽"]);

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style);
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));

    spinner
}

// main
fn main() {
    let args = Args::parse();
    
    let term = Term::stdout();


    assert!(Path::new(&args.file).exists(),"Path does not exist: {}", args.file);

    let _spinner = spinner("Loading config...");
    // load rules        
    let config_path = format!("{}\\appdata\\local\\PexeR\\config.toml", std::env::var("USERPROFILE").unwrap());
    let rules: config::Config = config::Config::from_toml(&fs::read_to_string(&config_path).expect("Failed to read config.toml")).expect("Failed to parse config.toml");
    let yara_rules = YARA::compile_rules(rules.yara.as_ref().unwrap()).unwrap();
    let vt_key: String = rules.vt.unwrap_or_default();
    _spinner.finish_with_message("Config loaded!");

    
    if args.graph {
        let _spinner = spinner("Loading directory...");
        // panic!("Graphing not yet implemented!");
        let files = std::fs::read_dir(&args.file).expect("Failed to read directory");
        let mut valid_files: Vec<pe_parser::PE_Data<'static>> = Vec::new();
        _spinner.finish_with_message("Directory loaded!");

        let _spinner = spinner("Graphing...");
        for file in files {
            let entry = file.unwrap();
            if entry.path().extension().map(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll")).unwrap_or(false)
            {
                let buffer = fs::read(entry.path()).expect("Failed to read file").into_boxed_slice();
                let buffer_ref: &'static [u8] = Box::leak(buffer);
                let name_ref: &'static str = Box::leak(entry.path().file_name().unwrap().to_string_lossy().to_string().into_boxed_str());

                // if args.lenient{
                //     let pe_data = pe_parser::lenient_parse(buffer_ref, name_ref).expect("Failed to parse, try lenient mode.");
                //     valid_files.push(pe_data);
                // }else{
                //     let pe_data = pe_parser::parse_pe(buffer_ref, name_ref).expect("Failed to parse, try lenient mode.");
                //     valid_files.push(pe_data);
                // }
                
                if let Ok(pe_data) = pe_parser::parse_pe(buffer_ref, name_ref) {
                    valid_files.push(pe_data);
                } else if let Ok(pe_data) = pe_parser::lenient_parse(buffer_ref, name_ref) {
                    valid_files.push(pe_data);
                } else {
                    eprintln!("Failed to parse file: {}", entry.path().display());
                }

            }
        }

        let graph = graph::build_import_graph(&valid_files);
        // term.write_line(&format!("Graph has {} nodes and {} edges", graph.node_count(), graph.edge_count())).unwrap();
        graph::print_graph(&graph, "graph.svg");
        _spinner.finish_with_message("Graphing complete!");
        // panic!("Graphing not fully implemented yet!");
        term.write_line(&format!("Graph saved to {}\\graph.svg", std::env::current_dir().unwrap().display())).unwrap();
        return
    }

    let _spinner = spinner("Processing file...");
    let buffer = fs::read(&args.file).expect("Failed to read file");
    _spinner.finish_with_message("File processed!");

    let _spinner = spinner("Hashing file...");
    // hash
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let hash_result = hasher.finalize();
    let pe_hash: String = hash_result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    _spinner.finish_with_message("File hashed!");

    let _spinner = spinner("Parsing PE file...");
    // parse PE
    let pe_data: pe_parser::PE_Data<'_>;

    if args.lenient {
        pe_data = pe_parser::lenient_parse(&buffer, &args.file).expect("Failed to parse PE file in lenient mode");
    } else {
        pe_data = pe_parser::parse_pe(&buffer, &args.file).expect("Failed to parse PE file");
    }
    _spinner.finish_with_message("PE file parsed!");

    if args.disassemble {
        let _spinner = spinner("Disassembling...");
        let offset = usize::from_str_radix(args.offset.strip_prefix("0x").unwrap_or(&args.offset),16).unwrap();
        // testing
        if pe_data.bitness{
            let segment: &[u8] = &buffer[offset..offset+512];
            let ip = pe_data.image_base;
            disassemble::disassemble(&segment, 64, offset as u64);
        }else{
            let segment: &[u8] = &buffer[offset..offset+512];
            let ip = pe_data.image_base;
            disassemble::disassemble(&segment,  32, offset as u64);
        }
        // panic!("testing");
        _spinner.finish_with_message("disassembled!");
        return;
    }

    let _spinner = spinner("Calculating entropy...");
    // calculate entropy
    let entropy = shannon_entropy(&buffer);
    _spinner.finish_with_message("Entropy calculated!");

    let _spinner = spinner("Extracting strings...");
    // extract strings
    let strings = strings::extract_strings(&buffer);
    _spinner.finish_with_message("Strings extracted!");

    let _spinner = spinner("Testing rules...");
    // test rules
    let rules = rules.rules.unwrap();
    let yara_matches = YARA::scan(&yara_rules, &buffer);
    let string_matches = strings::notable_strings(&strings, &rules);
    _spinner.finish_with_message("Rules tested!");

    // Deep mode analysis 
    let mut deep_scan_results: deep_scan::deep_scan_result = deep_scan::deep_scan_result::new();

    if args.deep {
        let spinner = spinner("Performing deep analysis...");
        // Packer detection
        // Overlay analysis
        deep_scan_results = deep_scan::deep_scan(&buffer, &pe_data).unwrap();

        // panic!("Deep scan not fully implemented yet!");

        spinner.finish_with_message("Deep analysis complete!");
    }

    let mut vt_data : HashMap<String, String> = HashMap::new();
    if args.vt {
        let spinner = spinner("Fetching VirusTotal data...");
        assert!(!vt_key.is_empty(), "VirusTotal API key not found in config.toml");
        vt_data = third_party::vt_fetch(&vt_key, &pe_hash);
        // term.write_line(&format!("VirusTotal data\n {:#?}", vt_data)).unwrap();
        spinner.finish_with_message("VirusTotal data fetched!");

        // panic!();
    }
    

    // Print tables
    // META DATA
    term.write_line(&style("\nMetadata").bold().green().to_string()).unwrap();
    let mut meta_table = Table::new();
    meta_table.add_row(Row::new(vec![Cell::new("PE Name"), Cell::new(&pe_data.name)]));
    meta_table.add_row(Row::new(vec![Cell::new("File Hash"), Cell::new(&pe_hash)]));
    meta_table.add_row(Row::new(vec![Cell::new("File Entropy"), Cell::new(&format!("{:.4}", entropy))]));
    meta_table.add_row(Row::new(vec![Cell::new("Verified Certificate"), Cell::new(&pe_data.certificates.to_string())]));
    meta_table.add_row(Row::new(vec![Cell::new("File Hash"), Cell::new(&pe_hash)]));
    if args.vt {
        meta_table.add_row(Row::new(vec![Cell::new("VirusTotal Description"), Cell::new(&vt_data.get("Type Description").unwrap_or(&"N/A".to_string()))]));
        meta_table.add_row(Row::new(vec![Cell::new("VirusTotal First Submission"), Cell::new(&vt_data.get("First Submission").unwrap_or(&"N/A".to_string()))]));
        meta_table.add_row(Row::new(vec![Cell::new("VirusTotal Last Analysis"), Cell::new(&vt_data.get("Last Analysis Stats").unwrap_or(&"N/A".to_string()))]));
        meta_table.add_row(Row::new(vec![Cell::new("VirusTotal Votes"), Cell::new(&vt_data.get("Votes").unwrap_or(&"N/A".to_string()))]));
        meta_table.add_row(Row::new(vec![Cell::new("VirusTotal Tags"), Cell::new(&vt_data.get("Tags").unwrap_or(&"N/A".to_string()))]));
    }
    meta_table.printstd();

    term.write_line("\n").unwrap();

    // SECTIONS
    term.write_line(&format!("{}",style("SECTIONS").bold().green())).unwrap();

    let mut section_table = Table::new();
    section_table.add_row(Row::new(vec![Cell::new("Name"), Cell::new("Raw Address"),Cell::new("Virtual Address"), Cell::new("Virtual Size")]));

    for section in pe_data.sections {
        section_table.add_row(Row::new(vec![Cell::new(String::from_utf8_lossy(&section.name).trim_matches('\0')), Cell::new(&format!("{:#x}", section.pointer_to_raw_data)),Cell::new(&format!("{:#x}", section.virtual_address)), Cell::new(&format!("{:#x}", section.virtual_size))]));
        
    }

    section_table.printstd();

    term.write_line("\n").unwrap();

    // IMPORTS
    let mut imports_by_dll: HashMap<String, Vec<String>> = HashMap::new();

    for import in pe_data.imports {
        imports_by_dll.entry(import.dll.to_string().clone())
            .or_default()
            .push(import.name.to_string());
    }

    // I don't actually think this is necessary if I just grab all the imports in the for loop
    let mut dlls = imports_by_dll.keys().cloned().collect::<Vec<String>>();
    dlls.sort();
    
    term.write_line(&format!("{}",style("IMPORTS").bold().green())).unwrap();
    let mut import_table = Table::new();
    for dll in dlls {
        let f = &imports_by_dll[&dll];
        import_table.add_row(Row::new(vec![Cell::new(&dll), Cell::new(&f.join("\n"))]));
        
    }
    import_table.printstd();

    term.write_line("\n").unwrap();

    // EXPORTS

    if !pe_data.exports.is_empty() {
        term.write_line(&format!("{}",style("EXPORTS").bold().green())).unwrap();
        let mut export_table = Table::new();
        export_table.add_row(Row::new(vec![Cell::new("Name"), Cell::new("Address")]));

        // handling for invalid exports - lenient_parse issues
        let valid_exports: Vec<_> = pe_data.exports.iter().filter(|e| e.offset.map(|o| o > 0).unwrap_or(false) && e.name.is_some())
        .collect();

        for export in valid_exports { 
            let name = export.name
                .unwrap_or("N/A")
                .trim_matches('\0')
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>();
            export_table.add_row(Row::new(vec![Cell::new(&truncate_str(&name, 80)), Cell::new(&format!("{}", export.offset.map(|o| format!("{:#x}", o)).unwrap_or_else(|| "N/A".to_string())))]));
        }
        export_table.printstd();
        term.write_line("\n").unwrap();
    }

    // DEEP SCAN RESULTS
    if deep_scan_results.results_found {
        term.write_line(&format!("{}",style("DEEP SCAN RESULTS").bold().green())).unwrap();
        
        // Anomalies
        let mut anomaly_table = Table::new();
        if deep_scan_results.anomalies.has_anomalies {
            anomaly_table.add_row(Row::new(vec![Cell::new("Anomaly"), Cell::new("Description")]));
            for anomaly in deep_scan_results.anomalies.anomalies {
                anomaly_table.add_row(Row::new(vec![Cell::new(&anomaly.name), Cell::new(&anomaly.description)]));
            }
        }
        anomaly_table.printstd();

        // Overlay
        let mut overlay_table = Table::new();
        if deep_scan_results.overlay.has_overlay {
            overlay_table.add_row(Row::new(vec![Cell::new("Section Name"),Cell::new("Overlay Offset"), Cell::new("Overlay Size")]));
            overlay_table.add_row(Row::new(vec![Cell::new(&deep_scan_results.overlay.section_name.unwrap()), Cell::new(&format!("{:#x}", deep_scan_results.overlay.overlay_offset.unwrap())), Cell::new(&format!("{:#x}", deep_scan_results.overlay.overlay_size.unwrap()))]));
        }
        overlay_table.printstd();

        // Packers

        term.write_line("\n").unwrap();
    }


    // RULES - if notable strings/yara match
    if !string_matches.is_empty() {
        term.write_line(&format!("{}",style("String Matches").bold().green())).unwrap();
        let mut strings_table = Table::new();
        strings_table.add_row(Row::new(vec![Cell::new("Rule"), Cell::new("Offset"), Cell::new("Value")]));   
        for (name, matches) in string_matches {
            for s in matches {
                strings_table.add_row(Row::new(vec![Cell::new(name), Cell::new(&format!("{:#x}", s.offset)), Cell::new(&truncate_str(&s.value, 80))]));
            }
        }
        strings_table.printstd();
    }

    if !yara_matches.as_ref().unwrap().is_empty() {
        term.write_line(&format!("{}",style("YARA Matches").bold().green())).unwrap();
        let mut yara_table = Table::new();
        for rule in yara_matches.unwrap() {
            yara_table.add_row(Row::new(vec![Cell::new("YARA Rule Match"),Cell::new(&rule)]));
        }
        yara_table.printstd();
    }


}