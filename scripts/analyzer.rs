#!/usr/bin/env -S cargo +nightly -Zscript --quiet
---cargo
[package]
edition = "2024"
[dependencies]
clap = { version = "4.2", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rayon = "1.7"
walkdir = "2.4"
regex = "1.10"
anyhow = "1.0"
---

use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

#[derive(Parser, Debug)]
#[command(
    name = "tech-stack-analyzer",
    about = "Analyze tech stack in development folders",
    version = "1.0"
)]
struct Args {
    /// Path to analyze (default: current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Number of worker threads
    #[arg(short, long, default_value_t = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4))]
    workers: usize,

    /// Save results to JSON file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Only output JSON, no pretty printing
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Clone, Serialize)]
struct FileAnalysis {
    file_path: String,
    language: String,
    dependencies: Vec<String>,
    size: usize,
    lines: usize,
}

#[derive(Debug, Serialize)]
struct DependencyInfo {
    name: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct LanguageInfo {
    name: String,
    file_count: usize,
    total_lines: usize,
    total_size: usize,
    top_dependencies: Vec<DependencyInfo>,
}

#[derive(Debug, Serialize)]
struct Summary {
    total_files_analyzed: usize,
    total_lines_of_code: usize,
    total_code_size_bytes: usize,
    languages_found: usize,
}

#[derive(Debug, Serialize)]
struct AnalysisResults {
    summary: Summary,
    languages: Vec<LanguageInfo>,
    top_dependencies_overall: Vec<DependencyInfo>,
}

struct TechStackAnalyzer {
    root_path: PathBuf,
    language_extensions: HashMap<&'static str, &'static str>,
    skip_directories: Vec<&'static str>,
    import_regexes: HashMap<&'static str, Vec<Regex>>,
    quiet: bool,
}

impl TechStackAnalyzer {
    fn new(root_path: PathBuf, quiet: bool) -> Result<Self> {
        let language_extensions = [
            (".py", "Python"),
            (".js", "JavaScript"),
            (".ts", "TypeScript"),
            (".jsx", "React/JSX"),
            (".tsx", "React/TSX"),
            (".rs", "Rust"),
            (".go", "Go"),
            (".java", "Java"),
            (".c", "C"),
            (".cpp", "C++"),
            (".cc", "C++"),
            (".cxx", "C++"),
            (".h", "C/C++ Header"),
            (".hpp", "C++ Header"),
            (".cs", "C#"),
            (".rb", "Ruby"),
            (".php", "PHP"),
            (".swift", "Swift"),
            (".kt", "Kotlin"),
            (".scala", "Scala"),
            (".clj", "Clojure"),
            (".ex", "Elixir"),
            (".exs", "Elixir"),
            (".hs", "Haskell"),
            (".ml", "OCaml"),
            (".fs", "F#"),
            (".r", "R"),
            (".dart", "Dart"),
            (".lua", "Lua"),
            (".sh", "Shell Script"),
            (".bash", "Bash"),
            (".zsh", "Zsh"),
            (".fish", "Fish"),
            (".ps1", "PowerShell"),
            (".sql", "SQL"),
            (".html", "HTML"),
            (".css", "CSS"),
            (".scss", "SCSS"),
            (".sass", "SASS"),
            (".less", "LESS"),
            (".vue", "Vue.js"),
            (".svelte", "Svelte"),
            (".elm", "Elm"),
            (".nim", "Nim"),
            (".zig", "Zig"),
            (".toml", "TOML Config"),
            (".yaml", "YAML Config"),
            (".yml", "YAML Config"),
            (".json", "JSON Config"),
            (".xml", "XML"),
            (".dockerfile", "Docker"),
            (".tf", "Terraform"),
            (".hcl", "HCL"),
        ]
        .into_iter()
        .collect();

        let skip_directories = vec![
            "node_modules",
            ".git",
            ".svn",
            ".hg",
            "__pycache__",
            ".pytest_cache",
            "target",
            "build",
            "dist",
            ".next",
            ".nuxt",
            ".idea",
            ".vscode",
            ".vs",
            "vendor",
            "deps",
            "_build",
        ];

        // Compile regexes for import detection
        let mut import_regexes: HashMap<&'static str, Vec<Regex>> = HashMap::new();

        import_regexes.insert(
            "Python",
            vec![
                Regex::new(r"^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*)")?,
                Regex::new(r"^\s*from\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+import")?,
            ],
        );

        import_regexes.insert(
            "JavaScript",
            vec![
                Regex::new(r#"^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"#)?,
                Regex::new(r#"^\s*const\s+.*?\s*=\s*require\(['"]([^'"]+)['"]\)"#)?,
                Regex::new(r#"^\s*import\(['"]([^'"]+)['"]\)"#)?,
            ],
        );

        import_regexes.insert(
            "TypeScript",
            vec![
                Regex::new(r#"^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"#)?,
                Regex::new(r#"^\s*import\(['"]([^'"]+)['"]\)"#)?,
            ],
        );

        import_regexes.insert(
            "React/JSX",
            vec![Regex::new(r#"^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"#)?],
        );

        import_regexes.insert(
            "React/TSX",
            vec![Regex::new(r#"^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"#)?],
        );

        import_regexes.insert(
            "Rust",
            vec![
                Regex::new(r"^\s*use\s+([a-zA-Z_][a-zA-Z0-9_]*)")?,
                Regex::new(r"^\s*extern\s+crate\s+([a-zA-Z_][a-zA-Z0-9_]*)")?,
            ],
        );

        import_regexes.insert("Go", vec![Regex::new(r#"^\s*import\s+['"]([^'"]+)['"]"#)?]);

        import_regexes.insert(
            "Java",
            vec![Regex::new(
                r"^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)",
            )?],
        );

        import_regexes.insert(
            "C#",
            vec![Regex::new(
                r"^\s*using\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)",
            )?],
        );

        Ok(Self {
            root_path,
            language_extensions,
            skip_directories,
            import_regexes,
            quiet,
        })
    }

    fn print_status(&self, message: &str) {
        if !self.quiet {
            println!("{}", message);
        }
    }

    fn get_file_language(&self, file_path: &Path) -> Option<&str> {
        // Special case for Docker files
        if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
            let lower_name = name.to_lowercase();
            if lower_name == "dockerfile"
                || lower_name == "dockerfile.dev"
                || lower_name == "dockerfile.prod"
            {
                return Some("Docker");
            }
        }

        file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| {
                let ext_with_dot = format!(".{}", ext.to_lowercase());
                self.language_extensions.get(ext_with_dot.as_str()).copied()
            })
    }

    fn extract_dependencies(&self, content: &str, language: &str) -> Vec<String> {
        let regexes = match self.import_regexes.get(language) {
            Some(regexes) => regexes,
            None => return Vec::new(),
        };

        let mut dependencies = Vec::new();

        for line in content.lines() {
            for regex in regexes {
                for cap in regex.captures_iter(line) {
                    if let Some(matched) = cap.get(1) {
                        let mut dep = matched.as_str().to_string();

                        // Clean up dependencies based on language
                        match language {
                            "Python" => {
                                dep = dep.split('.').next().unwrap_or(&dep).to_string();
                            }
                            "JavaScript" | "TypeScript" | "React/JSX" | "React/TSX" => {
                                // Skip relative imports
                                if dep.starts_with("./") || dep.starts_with("../") {
                                    continue;
                                }
                            }
                            "Rust" => {
                                dep = dep.split("::").next().unwrap_or(&dep).to_string();
                                // Skip internal Rust modules
                                if ["crate", "self", "super"].contains(&dep.as_str()) {
                                    continue;
                                }
                            }
                            "Java" => {
                                dep = dep.split('.').next().unwrap_or(&dep).to_string();
                            }
                            _ => {}
                        }

                        if !dep.is_empty() {
                            dependencies.push(dep);
                        }
                    }
                }
            }
        }

        dependencies
    }

    fn should_skip_dir(&self, entry: &DirEntry) -> bool {
        if let Some(name) = entry.file_name().to_str() {
            self.skip_directories.contains(&name)
        } else {
            false
        }
    }

    fn analyze_file(&self, file_path: &Path) -> Option<FileAnalysis> {
        let language = self.get_file_language(file_path)?;

        let content = fs::read_to_string(file_path).ok()?;

        // Skip empty files or very large files (>1MB)
        if content.trim().is_empty() || content.len() > 1024 * 1024 {
            return None;
        }

        let dependencies = self.extract_dependencies(&content, language);
        let lines = content.lines().count();

        Some(FileAnalysis {
            file_path: file_path.to_string_lossy().to_string(),
            language: language.to_string(),
            dependencies,
            size: content.len(),
            lines,
        })
    }

    fn collect_files(&self) -> Result<Vec<PathBuf>> {
        self.print_status(&format!("🔍 Scanning {}...", self.root_path.display()));

        let mut files = Vec::new();
        let mut skipped_dirs = std::collections::HashSet::new();

        for entry in WalkDir::new(&self.root_path).into_iter().filter_entry(|e| {
            if e.file_type().is_dir() && self.should_skip_dir(e) {
                if let Some(name) = e.file_name().to_str() {
                    skipped_dirs.insert(name.to_string());
                }
                false
            } else {
                true
            }
        }) {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }

        if !skipped_dirs.is_empty() {
            let common_skipped: Vec<_> = skipped_dirs
                .iter()
                .filter(|&d| {
                    ["node_modules", ".git", "target", "build", "dist"].contains(&d.as_str())
                })
                .collect();

            if !common_skipped.is_empty() {
                self.print_status(&format!(
                    "⏭️  Skipping common directories: {}",
                    common_skipped
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }

        self.print_status(&format!("📁 Found {} files to analyze", files.len()));
        Ok(files)
    }

    fn analyze_codebase(&self) -> Result<AnalysisResults> {
        let files = self.collect_files()?;

        // Use rayon for parallel processing
        let results: Vec<FileAnalysis> = files
            .par_iter()
            .filter_map(|file_path| self.analyze_file(file_path))
            .collect();

        Ok(self.aggregate_results(results))
    }

    fn aggregate_results(&self, results: Vec<FileAnalysis>) -> AnalysisResults {
        if results.is_empty() {
            return AnalysisResults {
                summary: Summary {
                    total_files_analyzed: 0,
                    total_lines_of_code: 0,
                    total_code_size_bytes: 0,
                    languages_found: 0,
                },
                languages: Vec::new(),
                top_dependencies_overall: Vec::new(),
            };
        }

        // Collect stats per language
        let mut language_stats: HashMap<String, (usize, usize, usize)> = HashMap::new(); // (file_count, total_lines, total_size)
        let mut language_deps: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut all_dependencies: HashMap<String, usize> = HashMap::new();

        for result in &results {
            let (file_count, total_lines, total_size) = language_stats
                .entry(result.language.clone())
                .or_insert((0, 0, 0));

            *file_count += 1;
            *total_lines += result.lines;
            *total_size += result.size;

            let lang_deps = language_deps
                .entry(result.language.clone())
                .or_insert_with(HashMap::new);

            for dep in &result.dependencies {
                *lang_deps.entry(dep.clone()).or_insert(0) += 1;
                *all_dependencies.entry(dep.clone()).or_insert(0) += 1;
            }
        }

        // Convert to LanguageInfo structs and sort by file count
        let mut languages: Vec<LanguageInfo> = language_stats
            .into_iter()
            .map(|(name, (file_count, total_lines, total_size))| {
                let binding = HashMap::new();
                let deps = language_deps.get(&name).unwrap_or(&binding);
                let mut deps_vec: Vec<_> = deps
                    .iter()
                    .map(|(k, v)| DependencyInfo {
                        name: k.clone(),
                        count: *v,
                    })
                    .collect();
                deps_vec.sort_by(|a, b| b.count.cmp(&a.count));
                deps_vec.truncate(20); // Keep top 20

                LanguageInfo {
                    name,
                    file_count,
                    total_lines,
                    total_size,
                    top_dependencies: deps_vec,
                }
            })
            .collect();

        // Sort languages by file count
        languages.sort_by(|a, b| b.file_count.cmp(&a.file_count));

        // Sort overall dependencies
        let mut top_dependencies_overall: Vec<DependencyInfo> = all_dependencies
            .into_iter()
            .map(|(name, count)| DependencyInfo { name, count })
            .collect();
        top_dependencies_overall.sort_by(|a, b| b.count.cmp(&a.count));
        top_dependencies_overall.truncate(30); // Keep top 30

        let total_files = results.len();
        let total_lines: usize = results.iter().map(|r| r.lines).sum();
        let total_size: usize = results.iter().map(|r| r.size).sum();

        AnalysisResults {
            summary: Summary {
                total_files_analyzed: total_files,
                total_lines_of_code: total_lines,
                total_code_size_bytes: total_size,
                languages_found: languages.len(),
            },
            languages,
            top_dependencies_overall,
        }
    }

    fn print_results(&self, results: &AnalysisResults) {
        println!("\n{}", "=".repeat(60));
        println!("🚀 TECH STACK ANALYSIS RESULTS");
        println!("{}", "=".repeat(60));

        let summary = &results.summary;
        println!("\n📊 SUMMARY:");
        println!(
            "   • Files analyzed: {}",
            format_number(summary.total_files_analyzed)
        );
        println!(
            "   • Lines of code: {}",
            format_number(summary.total_lines_of_code)
        );
        println!(
            "   • Code size: {:.1} MB",
            summary.total_code_size_bytes as f64 / 1024.0 / 1024.0
        );
        println!("   • Languages found: {}", summary.languages_found);

        println!("\n🗣️  LANGUAGES BY USAGE:");
        let total_files = summary.total_files_analyzed as f64;

        for (i, lang_info) in results.languages.iter().enumerate() {
            let percent = (lang_info.file_count as f64 / total_files) * 100.0;
            println!(
                "   {:2}. {:15} {:>6} files ({:5.1}%) - {:>8} lines",
                i + 1,
                lang_info.name,
                lang_info.file_count,
                percent,
                format_number(lang_info.total_lines)
            );
        }

        println!("\n📦 TOP DEPENDENCIES (All Languages):");
        for (i, dep_info) in results.top_dependencies_overall.iter().take(15).enumerate() {
            println!(
                "   {:2}. {:25} {:>4} occurrences",
                i + 1,
                dep_info.name,
                dep_info.count
            );
        }

        println!("\n🔍 LANGUAGE-SPECIFIC DEPENDENCIES:");
        for lang_info in &results.languages {
            if !lang_info.top_dependencies.is_empty() {
                println!("\n   {}:", lang_info.name);
                for dep_info in lang_info.top_dependencies.iter().take(10) {
                    println!("      • {:20} {:>3}x", dep_info.name, dep_info.count);
                }
            }
        }
    }
}

fn format_number(n: usize) -> String {
    if n < 1000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{},{:03}", n / 1000, n % 1000)
    } else {
        format!(
            "{},{:03},{:03}",
            n / 1_000_000,
            (n % 1_000_000) / 1000,
            n % 1000
        )
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Set up rayon thread pool if specified
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers)
        .build_global()
        .context("Failed to initialize thread pool")?;

    let analyzer =
        TechStackAnalyzer::new(args.path, args.quiet).context("Failed to initialize analyzer")?;

    let results = analyzer
        .analyze_codebase()
        .context("Failed to analyze codebase")?;

    if let Some(output_path) = args.output {
        let json_output =
            serde_json::to_string_pretty(&results).context("Failed to serialize results")?;
        fs::write(&output_path, json_output).context("Failed to write output file")?;
        analyzer.print_status(&format!("💾 Results saved to {}", output_path.display()));
    }

    if args.quiet {
        let json_output = serde_json::to_string(&results).context("Failed to serialize results")?;
        println!("{}", json_output);
    } else {
        analyzer.print_results(&results);
    }

    Ok(())
}
