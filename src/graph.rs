use goblin::pe::import;
use petgraph::graph::UnGraph;
use petgraph::visit::NodeIndexable;
use petgraph::graph::DiGraph;
use std::collections::HashMap;
use petgraph::dot::{Dot, Config};
use layout::backends::svg::SVGWriter;
use layout::core::base::Orientation;
use layout::core::geometry::Point;
use layout::core::style::StyleAttr;
use layout::core::utils::save_to_file;
use layout::std_shapes::shapes::{Arrow, Element, ShapeKind};
use layout::topo::layout::VisualGraph;

use crate::pe_parser;

// I no math good and graph hurt brain
// This is the only real AI-heavy portion of the code base

fn is_pe_filename(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".dll") || lower.ends_with(".exe")
}

//https://docs.rs/petgraph/latest/petgraph/index.html#examples
pub fn build_import_graph<'a>(pe_files: &'a [pe_parser::PE_Data<'a>]) -> DiGraph<String, String> {
    let mut graph = DiGraph::new();
    let mut node_indices = HashMap::new();

    // Add a node for every PE file
    for pe in pe_files {
        if is_pe_filename(pe.name) {
            let idx = graph.add_node(pe.name.to_string());
            node_indices.insert(pe.name.to_lowercase(), idx);
        }
    }

    // For each file, check its imports against known files in the slice
    for pe in pe_files {
        if pe.imports.is_empty() {
            continue; // Skip files with no imports
        }

        if is_pe_filename(pe.name) {
            let from = node_indices[&pe.name.to_lowercase()];
            for import in &pe.imports {

            // not ideal, but necessary to avoid exceeding call stack size
            if import.name.to_string().len() < 3 {
                continue; // Skip empty imports
            }
            let dep = import.dll.to_lowercase();

            if let Some(&to) = node_indices.get(&dep) {
                graph.update_edge(from, to, import.name.to_string());
            }
        }
        } else {
            continue; // Skip files that don't look like PE files
        }


    }

    graph
}

// pub fn print_graph(graph: &DiGraph<String, String>) {
//     // println!("{}", Dot::with_config(graph, &[Config::EdgeNoLabel]));
    
// }

pub fn print_graph(graph: &DiGraph<String, String>, out_path: &str) {
    let mut vg = VisualGraph::new(Orientation::LeftToRight);
    let mut handle_map = HashMap::new();

    // Add a node for every vertex in the DiGraph
    for idx in graph.node_indices() {
        let label = &graph[idx];
        // Use just the filename, not the full path, to keep nodes readable
        let short_label = std::path::Path::new(label)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| label.clone());

        let shape = ShapeKind::new_box(&short_label);
        let style = StyleAttr::simple();
        // should size element base on length of text at some point
        let size = Point::new(200., 50.);
        let element = Element::create(shape, style, Orientation::LeftToRight, size);
        let handle = vg.add_node(element);
        handle_map.insert(idx, handle);
    }

    // Add a directed edge for every edge in the DiGraph
    for edge in graph.edge_indices() {
        let (src, dst) = graph.edge_endpoints(edge).unwrap();
        let arrow = Arrow::simple("");  // swap "" for &graph[edge] if you want labels
        vg.add_edge(arrow, handle_map[&src], handle_map[&dst]);
    }

    // Render to SVG
    let mut svg = SVGWriter::new();
    vg.do_it(false, false, false, &mut svg);
    let svg_content = svg.finalize();
    save_to_file(out_path, &svg_content).expect("Failed to write SVG");
}