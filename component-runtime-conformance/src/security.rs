//! Smoke-test the portable malicious components, not Kinetix host policy.
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::path::PathBuf;
use wasmtime::{
    component::{Component, Linker, Val},
    Config, Engine, Store,
};

fn main() -> Result<()> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: security-fixture-smoke <fixture-directory>")?,
    );
    let vectors: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("cases.json"))?)?;
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| anyhow!("{e:#}"))?;
    let probe_component = Component::from_file(&engine, directory.join("probe.wasm"))
        .map_err(|e| anyhow!("{e:#}"))?;
    let mut linker = Linker::<()>::new(&engine);
    // Only the base probe's contract imports receive trapping implementations.
    // Forbidden imports appended to ambient components remain unresolved.
    linker
        .define_unknown_imports_as_traps(&probe_component)
        .map_err(|e| anyhow!("{e:#}"))?;
    for ambient in vectors["ambient_imports"].as_array().unwrap() {
        let id = ambient["id"].as_str().unwrap();
        let component = Component::from_file(
            &engine,
            directory.join("ambient").join(format!("{id}.wasm")),
        )
        .map_err(|e| anyhow!("{e:#}"))?;
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000).map_err(|e| anyhow!("{e:#}"))?;
        let result = linker.instantiate(&mut store, &component);
        ensure!(result.is_err(), "ambient import {id} unexpectedly linked");
        let message = format!("{:#}", result.err().unwrap());
        ensure!(
            message.contains(ambient["import"].as_str().unwrap()),
            "{id} failed for an unrelated reason: {message}"
        );
        // Positive control: a fallback linker fills the ambient import and
        // accepts the same component, which is forbidden in production.
        linker
            .define_unknown_imports_as_traps(&component)
            .map_err(|e| anyhow!("{e:#}"))?;
        let mut permissive_store = Store::new(&engine, ());
        permissive_store
            .set_fuel(1_000_000)
            .map_err(|e| anyhow!("{e:#}"))?;
        linker
            .instantiate(&mut permissive_store, &component)
            .map_err(|e| anyhow!("{id} positive control failed: {e:#}"))?;
    }

    // Complete API-v1 exports make these packages loadable by typed hosts;
    // capabilities absent from the manifest must return a real denial.
    for (interface_name, function_name, arity) in [
        ("credential-strategy", "resolve", 3),
        ("credential-strategy", "health", 2),
        ("credential-strategy", "rotate", 2),
        ("model-source", "discover", 3),
        ("routing-facts", "facts", 1),
        ("hooks", "on-request-normalized", 1),
        ("hooks", "on-target-candidate", 1),
        ("hooks", "on-usage-finalized", 1),
    ] {
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000).map_err(|e| anyhow!("{e:#}"))?;
        let instance = linker
            .instantiate(&mut store, &probe_component)
            .map_err(|e| anyhow!("{e:#}"))?;
        let interface = instance
            .get_export_index(&mut store, None, interface_name)
            .context("missing API-v1 interface")?;
        let index = instance
            .get_export_index(&mut store, Some(&interface), function_name)
            .context("missing API-v1 function")?;
        let function = instance.get_func(&mut store, index).unwrap();
        let params = vec![Val::String("fixture".into()); arity];
        let mut results = [Val::Result(Ok(None))];
        function
            .call(&mut store, &params, &mut results)
            .map_err(|e| anyhow!("{e:#}"))?;
        let Val::Result(Err(Some(error))) = &results[0] else {
            bail!("undeclared {interface_name}.{function_name} did not deny");
        };
        let Val::Record(fields) = error.as_ref() else {
            bail!("denial is not a plugin-error");
        };
        ensure!(
            fields.iter().any(|(name, value)| name == "code"
                && matches!(value, Val::String(code) if code == "permission_denied")),
            "undeclared export did not return permission_denied"
        );
    }
    for case in vectors["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000).map_err(|e| anyhow!("{e:#}"))?;
        let instance = linker
            .instantiate(&mut store, &probe_component)
            .map_err(|e| anyhow!("{e:#}"))?;
        let interface = instance
            .get_export_index(&mut store, None, "health-probe")
            .context("missing health-probe interface")?;
        let index = instance
            .get_export_index(&mut store, Some(&interface), "probe")
            .context("missing probe function")?;
        let probe = instance.get_func(&mut store, index).unwrap();
        let params = [
            Val::String("fixture".into()),
            Val::String(case["operation"].to_string()),
        ];
        let mut results = [Val::Result(Ok(None))];
        let result = probe.call(&mut store, &params, &mut results);
        if case["operation"]["op"] == "error" {
            result.map_err(|e| anyhow!("{e:#}"))?;
            ensure!(
                matches!(&results[0], Val::Result(Err(Some(_)))),
                "{id} did not return the malicious error"
            );
        } else {
            match result {
                Err(error) => ensure!(
                    format!("{error:#}").contains("unknown import"),
                    "{id} failed without reaching a host import: {error:#}"
                ),
                Ok(()) => bail!("{id} did not call its host capability"),
            }
        }
    }
    println!("Security fixtures reach their host calls; ambient imports fail linking");
    Ok(())
}
