use anyhow::Result;
use clap::{Parser, Subcommand};
use model::{
    AdmissionResult as AdmissionResultImpl, AnalysisReport as AnalysisReportImpl, BuildReport,
    Config,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use dedup::DedupResult as DedupResultImpl;
use emit::EmitResult as EmitResultImpl;
use fetch::{FetchMode, FetchedSource, ListsLock};
use model::util::{sha256_hex, write_json, write_text, write_tsv};
use rewrite::RewriteResult as RewriteResultImpl;

#[derive(Debug, Parser)]
#[command(
    name = "rustshield",
    version,
    about = "Offline RustShield.txt generator"
)]
struct Args {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, default_value = "config/sources.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Build {
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        offline: bool,
    },
    Analyze,
    Verify {
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    Bench {
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    Resources,
    UpdatePins,
}

struct Pipeline {
    config: Config,
    sources: Vec<FetchedSource>,
    lock: ListsLock,
    lock_hash: String,
    config_hash: String,
    profile_hash: String,
    build_id: String,
    records: Vec<model::ParsedRecord>,
    admission: AdmissionResultImpl,
    dedup: DedupResultImpl,
    rewrite: RewriteResultImpl,
    emit: EmitResultImpl,
    resources: Vec<adblock::resources::Resource>,
}

impl Pipeline {
    fn run(root: PathBuf, config_path: PathBuf, fetch_mode: FetchMode) -> Result<Self> {
        let started = Instant::now();
        let config = Config::load(&config_path)?;
        let config_hash = config.config_hash(&config_path)?;
        let profile_hash = config.profile_hash(&root);
        let (sources, lock) = fetch::fetch_all_with_mode(&config, &root, fetch_mode)?;
        timing("fetch", started.elapsed());
        let lock_bytes = lock.to_bytes()?;
        let lock_hash = sha256_hex(&lock_bytes);
        let build_material = format!(
            "{config_hash}\n{lock_hash}\n{profile_hash}\n{}\n{}",
            config.engine.adblock_version, config.output.emit_order
        );
        let build_id = sha256_hex(build_material.as_bytes());
        let started = Instant::now();
        let records = parse::parse_sources(&sources, &root, &config)?;
        timing("parse", started.elapsed());
        let started = Instant::now();
        let admission = admit::admit(&records, &config, &root)?;
        timing("admit", started.elapsed());
        let started = Instant::now();
        let dedup = dedup::dedup(admission.accepted.clone())?;
        timing("dedup", started.elapsed());
        let started = Instant::now();
        let rewrite = rewrite::rewrite(dedup.rules.clone(), &config)?;
        timing("rewrite", started.elapsed());
        let started = Instant::now();
        let emit = emit::emit(
            &rewrite.rules,
            &config,
            &build_id,
            &admission.badfilter_targets,
        )?;
        timing("emit", started.elapsed());
        let started = Instant::now();
        let resources = engine_resources(&config, &root);
        timing("resources", started.elapsed());
        Ok(Self {
            config,
            sources,
            lock,
            lock_hash,
            config_hash,
            profile_hash,
            build_id,
            records,
            admission,
            dedup,
            rewrite,
            emit,
            resources,
        })
    }

    fn verify(&self, candidate_text: &str) -> Result<model::VerifyReport> {
        verify::verify(
            &self.config,
            &self.admission.baseline,
            &self.emit.rules,
            candidate_text,
            &self.emit.text,
            &self.resources,
            &self.rewrite.receipts,
        )
    }

    fn bench(&self, candidate_text: &str) -> model::BenchReport {
        verify::bench(
            &self.config,
            &self.admission.baseline,
            candidate_text,
            &self.resources,
            &self.config.output.emit_order,
        )
    }

    fn analysis(&self) -> Result<AnalysisReportImpl> {
        analyze::analyze(
            &self.records,
            &self.admission,
            &self.emit.rules,
            &self.config,
        )
    }
}

fn timing(label: &str, elapsed: std::time::Duration) {
    if std::env::var_os("RUSTSHIELD_TIMING").is_some() {
        eprintln!("{label}: {}ms", elapsed.as_millis());
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = fs::canonicalize(&args.root)?;
    let config_path = if args.config.is_absolute() {
        args.config.clone()
    } else {
        root.join(&args.config)
    };

    match args.command {
        Command::Build { no_verify, offline } => build(
            &root,
            &config_path,
            no_verify,
            if offline {
                FetchMode::Offline
            } else {
                FetchMode::Online
            },
        ),
        Command::Analyze => analyze_command(&root, &config_path),
        Command::Verify { candidate } => verify_command(&root, &config_path, candidate),
        Command::Bench { candidate } => bench_command(&root, &config_path, candidate),
        Command::Resources => resources_command(&root, &config_path),
        Command::UpdatePins => update_pins(&config_path),
    }
}

fn build(root: &Path, config_path: &Path, no_verify: bool, fetch_mode: FetchMode) -> Result<()> {
    let pipeline = Pipeline::run(root.to_path_buf(), config_path.to_path_buf(), fetch_mode)?;

    let lock_path = fetch::lock_path(root, &pipeline.config);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&lock_path, pipeline.lock.to_bytes()?)?;

    let verify_started = Instant::now();
    let verification = if no_verify {
        model::VerifyReport {
            required: pipeline.config.verify.required,
            mismatches: Vec::new(),
            cases_checked: 0,
            golden_rule_violations: 0,
            emit_order_violations: 0,
            ..Default::default()
        }
    } else {
        pipeline.verify(&pipeline.emit.text)?
    };
    timing("verify", verify_started.elapsed());
    let started = Instant::now();
    let bench = pipeline.bench(&pipeline.emit.text);
    timing("bench", started.elapsed());
    let analysis = pipeline.analysis()?;
    let report = build_report(&pipeline, &analysis, &verification, &bench);
    let output_name = pipeline
        .config
        .output
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "RustShield.txt".to_string());

    let staging = root.join(format!("out/.staging-{}", pipeline.build_id));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(staging.join("reports"))?;
    let list_path = staging.join("RustShield.txt");
    write_text(&list_path, &pipeline.emit.text)?;
    write_text(
        &staging.join(format!("{output_name}.sha256")),
        &format!(
            "{}  {output_name}\n",
            sha256_hex(pipeline.emit.text.as_bytes())
        ),
    )?;
    write_json(&staging.join("reports/manifest.json"), &manifest(&pipeline))?;
    write_json(&staging.join("reports/build.json"), &report)?;
    write_json(&staging.join("reports/analysis.json"), &analysis)?;
    write_json(
        &staging.join("reports/admitted_resources.json"),
        &pipeline.admission.resource_decisions,
    )?;
    write_json(&staging.join("reports/verify.json"), &verification)?;
    write_json(&staging.join("reports/bench.json"), &bench)?;
    write_tsv(
        &staging.join("reports/rewrites.tsv"),
        "id\tfamily\tbefore\tchecks\tafter",
        pipeline
            .rewrite
            .receipts
            .iter()
            .map(|receipt| receipt.tsv_row()),
    )?;
    let exclusion_rows: Vec<String> = pipeline
        .admission
        .excluded
        .iter()
        .map(|row| row.tsv_row())
        .collect();
    write_tsv(
        &staging.join("reports/excluded.tsv"),
        "source\tline\tdialect\treason\ttext",
        exclusion_rows.iter().cloned(),
    )?;
    write_tsv(
        &staging.join("reports/dropped.tsv"),
        "source\tline\tdialect\treason\ttext",
        exclusion_rows.iter().cloned(),
    )?;
    write_tsv(
        &staging.join("reports/dialect_gaps.tsv"),
        "source\tline\tdialect\tkind\tclass\tdetail",
        gap_rows(&pipeline),
    )?;
    write_text(
        &staging.join("reports/build.md"),
        &build_markdown(&report, &analysis, &verification, &bench),
    )?;

    let blocked = verification.required
        && verification.mismatches.len() > pipeline.config.verify.max_mismatches;
    if blocked {
        eprintln!(
            "verification blocked publish: {} mismatch(es); artifacts left in {}",
            verification.mismatches.len(),
            staging.display()
        );
        std::process::exit(2);
    }

    publish(root, &staging, &pipeline.config.output.path)?;
    println!(
        "built {} with {} rules (dedup -{}, rewrites {})",
        root.join(&pipeline.config.output.path).display(),
        pipeline.emit.rules.len(),
        pipeline.dedup.duplicate_exact + pipeline.dedup.duplicate_semantic,
        pipeline.rewrite.receipts.len()
    );
    Ok(())
}

fn publish(root: &Path, staging: &Path, output_path: &Path) -> Result<()> {
    let output_root = root.join(output_path.parent().unwrap_or_else(|| Path::new("")));
    fs::create_dir_all(&output_root)?;
    let name = output_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "RustShield.txt".to_string());
    let output = output_root.join(&name);
    if output.exists() {
        let prev = output_root.join(format!("{name}.prev"));
        if prev.exists() {
            fs::remove_file(&prev)?;
        }
        fs::rename(&output, prev)?;
    }
    fs::rename(staging.join("RustShield.txt"), output)?;
    fs::rename(
        staging.join(format!("{name}.sha256")),
        output_root.join(format!("{name}.sha256")),
    )?;

    let reports = output_root.join("reports");
    if reports.exists() {
        fs::remove_dir_all(&reports)?;
    }
    fs::rename(staging.join("reports"), reports)?;
    Ok(())
}

fn analyze_command(root: &Path, config_path: &Path) -> Result<()> {
    let pipeline = Pipeline::run(
        root.to_path_buf(),
        config_path.to_path_buf(),
        FetchMode::Online,
    )?;
    let analysis = pipeline.analysis()?;
    println!("{}", serde_json::to_string_pretty(&analysis)?);
    Ok(())
}

fn verify_command(root: &Path, config_path: &Path, candidate: Option<PathBuf>) -> Result<()> {
    let pipeline = Pipeline::run(
        root.to_path_buf(),
        config_path.to_path_buf(),
        FetchMode::Online,
    )?;
    let text = match candidate {
        Some(path) => fs::read_to_string(root.join(path))?,
        None => pipeline.emit.text.clone(),
    };
    let report = pipeline.verify(&text)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.mismatches.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

fn bench_command(root: &Path, config_path: &Path, candidate: Option<PathBuf>) -> Result<()> {
    let pipeline = Pipeline::run(
        root.to_path_buf(),
        config_path.to_path_buf(),
        FetchMode::Online,
    )?;
    let text = match candidate {
        Some(path) => fs::read_to_string(root.join(path))?,
        None => pipeline.emit.text.clone(),
    };
    println!("{}", serde_json::to_string_pretty(&pipeline.bench(&text))?);
    Ok(())
}

fn resources_command(root: &Path, config_path: &Path) -> Result<()> {
    let pipeline = Pipeline::run(
        root.to_path_buf(),
        config_path.to_path_buf(),
        FetchMode::Online,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&pipeline.admission.resource_decisions)?
    );
    Ok(())
}

fn update_pins(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let text = fs::read_to_string(config_path)?;
    let mut pins = BTreeMap::new();
    for source in &config.source {
        if source.url.starts_with("http://") || source.url.starts_with("https://") {
            pins.insert(source.id.clone(), fetch::current_sha256(&source.url)?);
        }
    }

    let mut updated = Vec::new();
    let mut in_source = false;
    let mut current_id: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed == "[[source]]" {
            in_source = true;
            current_id = None;
            updated.push(line.to_string());
            continue;
        }
        if in_source && trimmed.starts_with("id =") {
            current_id = trimmed.split('"').nth(1).map(str::to_string);
        }
        if in_source && trimmed.starts_with("sha256 =") {
            if let Some(digest) = current_id.as_ref().and_then(|id| pins.get(id)) {
                let indent = " ".repeat(line.len() - trimmed.len());
                updated.push(format!("{indent}sha256 = \"{digest}\""));
                continue;
            }
        }
        updated.push(line.to_string());
    }

    fs::write(config_path, format!("{}\n", updated.join("\n")))?;
    for (id, digest) in pins {
        println!("{id}\t{digest}");
    }
    Ok(())
}

fn engine_resources(config: &Config, root: &Path) -> Vec<adblock::resources::Resource> {
    let Some(resources) = &config.resources else {
        return Vec::new();
    };
    let ubo = &resources.ubo;
    let Some(path) = ubo.snapshot_path.as_ref() else {
        return Vec::new();
    };
    model::ResourceCatalog::load_verified(&root.join(path), &ubo.snapshot_sha256)
        .map(|catalog| catalog.engine_resources())
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
struct Manifest {
    build_id: String,
    config_hash: String,
    profile_hash: String,
    lists_lock_hash: String,
    adblock_version: String,
    engine_profile: String,
    emit_order: String,
    sources: Vec<String>,
}

fn manifest(pipeline: &Pipeline) -> Manifest {
    Manifest {
        build_id: pipeline.build_id.clone(),
        config_hash: pipeline.config_hash.clone(),
        profile_hash: pipeline.profile_hash.clone(),
        lists_lock_hash: pipeline.lock_hash.clone(),
        adblock_version: pipeline.config.engine.adblock_version.clone(),
        engine_profile: pipeline.config.engine.profile.clone(),
        emit_order: pipeline.config.output.emit_order.clone(),
        sources: pipeline
            .sources
            .iter()
            .map(|source| source.config.id.clone())
            .collect(),
    }
}

fn build_report(
    pipeline: &Pipeline,
    analysis: &AnalysisReportImpl,
    verification: &model::VerifyReport,
    bench: &model::BenchReport,
) -> BuildReport {
    let mut report = BuildReport::new(
        pipeline.build_id.clone(),
        pipeline.config_hash.clone(),
        pipeline.profile_hash.clone(),
        pipeline.lock_hash.clone(),
        &pipeline.config,
    );
    report.metrics.extend(analysis.metrics.clone());
    report.metric("duplicates_exact", pipeline.dedup.duplicate_exact);
    report.metric("duplicates_semantic", pipeline.dedup.duplicate_semantic);
    report.metric("rewrites_applied", pipeline.rewrite.receipts.len());
    report.metric("output_lines", pipeline.emit.rules.len());
    report.metric("excluded_by_gate", pipeline.admission.excluded.len());
    report.metric(
        "golden_rule_violations",
        verification.golden_rule_violations,
    );
    report.metric("decision_mismatches", verification.mismatches.len());
    report.metric("verify_cases", verification.cases_checked);
    report.metric(
        "network_rules_probed",
        verification.coverage.network_rules_probed,
    );
    report.metric(
        "network_rules_total",
        verification.coverage.network_rules_total,
    );
    report.metric(
        "receipts_exercised",
        verification.coverage.rewrite_receipts_exercised,
    );
    report.metric(
        "cosmetic_hosts_checked",
        verification.coverage.cosmetic_hosts_checked,
    );
    report.metric(
        "cosmetic_hosts_total",
        verification.coverage.cosmetic_hosts_total,
    );
    report.receipts = pipeline.rewrite.receipts.clone();
    report.verification = verification.clone();
    report.bench = bench.clone();
    report
}

fn gap_rows(pipeline: &Pipeline) -> Vec<String> {
    let mut rows = Vec::new();
    for record in &pipeline.records {
        let gaps: &[model::DialectGap] = match &record.outcome {
            model::ParsedOutcome::Network(rule) => &rule.dialect_gaps,
            model::ParsedOutcome::Cosmetic(rule) => &rule.dialect_gaps,
            model::ParsedOutcome::Unsupported { gap, .. } => {
                gap.as_ref().map(std::slice::from_ref).unwrap_or_default()
            }
            _ => &[],
        };
        for gap in gaps {
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                record.source_id,
                record.line_no,
                record.dialect.as_str(),
                gap.kind,
                gap.class.as_str(),
                gap.detail.replace('\t', " ")
            ));
        }
    }
    rows
}

fn build_markdown(
    report: &BuildReport,
    analysis: &AnalysisReportImpl,
    verification: &model::VerifyReport,
    bench: &model::BenchReport,
) -> String {
    let mut output = String::new();
    output.push_str("# RustShield build\n\n");
    output.push_str(&format!("- build id: `{}`\n", report.build_id));
    output.push_str(&format!(
        "- emitted rules: `{}`\n",
        report
            .metrics
            .get("output_lines")
            .map(serialize_value)
            .unwrap_or_default()
    ));
    output.push_str(&format!(
        "- parse errors: `{}`\n",
        analysis
            .metrics
            .get("parse_errors")
            .map(serialize_value)
            .unwrap_or_default()
    ));
    output.push_str(&format!("- rewrites: `{}`\n", report.receipts.len()));
    output.push_str(&format!(
        "- mismatches: `{}`\n",
        verification.mismatches.len()
    ));
    output.push_str(&format!(
        "- verification cases: `{}` (network rules `{}`/`{}`, receipts `{}`/`{}`, cosmetic hosts `{}`/`{}`)\n",
        verification.cases_checked,
        verification.coverage.network_rules_probed,
        verification.coverage.network_rules_total,
        verification.coverage.rewrite_receipts_exercised,
        verification.coverage.rewrite_receipts_total,
        verification.coverage.cosmetic_hosts_checked,
        verification.coverage.cosmetic_hosts_total,
    ));
    output.push_str(&format!(
        "- flatbuffer bytes: admitted `{}`, candidate `{}`\n",
        bench.admitted_opt_bytes, bench.candidate_opt_bytes
    ));
    output.push_str(&format!(
        "- engine build ms: admitted `{}`, candidate `{}`\n",
        bench.admitted_build_ms, bench.candidate_build_ms
    ));
    output
}

fn serialize_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}
