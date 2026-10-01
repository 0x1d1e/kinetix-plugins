//! Smoke-test the portable malicious components, not Kinetix host policy.
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::path::PathBuf;
use wasmtime::{
    component::{types::ComponentItem, Component, Linker, Resource, ResourceType, Val},
    Config, Engine, Store,
};

// Test-only linker: accept inert types and dependency functions, optionally
// withholding just the named authority-bearing operation. No native WASI.
fn ambient_linker(
    engine: &Engine,
    component: &Component,
    withheld: Option<(&str, &str)>,
    setup_resources: bool,
) -> Result<Linker<()>> {
    let mut linker = Linker::new(engine);
    for (interface_name, import) in component.component_type().imports(engine) {
        let ComponentItem::ComponentInstance(interface) = import.ty else {
            bail!("unexpected non-interface import {interface_name}");
        };
        let mut instance = linker
            .instance(interface_name)
            .map_err(|e| anyhow!("{e:#}"))?;
        for (name, export) in interface.exports(engine) {
            match export.ty {
                ComponentItem::Resource(_) => {
                    instance
                        .resource(name, ResourceType::host::<()>(), |_, _| Ok(()))
                        .map_err(|e| anyhow!("{e:#}"))?;
                }
                ComponentItem::ComponentFunc(_) => {
                    if withheld == Some((interface_name, name)) {
                        continue;
                    }
                    let qualified = format!("{interface_name}#{name}");
                    // Supply inert fake resources so filesystem and HTTP probes
                    // reach open-at/handle, not merely their prerequisite calls.
                    let preopens = setup_resources
                        && qualified == "wasi:filesystem/preopens@0.2.0#get-directories";
                    let constructor = setup_resources
                        && interface_name == "wasi:http/types@0.2.0"
                        && matches!(
                            name,
                            "[constructor]fields" | "[constructor]outgoing-request"
                        );
                    let setter = setup_resources
                        && interface_name == "wasi:http/types@0.2.0"
                        && matches!(
                            name,
                            "[method]outgoing-request.set-scheme"
                                | "[method]outgoing-request.set-authority"
                                | "[method]outgoing-request.set-path-with-query"
                        );
                    instance
                        .func_new(name, move |mut store, _, params, results| {
                            // Dynamic resource values, including borrows, need
                            // explicit release before this host call returns.
                            for param in params {
                                if let Val::Resource(resource) = param {
                                    resource.resource_drop(&mut store)?;
                                }
                            }
                            if preopens || constructor {
                                let resource =
                                    Resource::<()>::new_own(0).try_into_resource_any(&mut store)?;
                                results[0] = if preopens {
                                    Val::List(vec![Val::Tuple(vec![
                                        Val::Resource(resource),
                                        Val::String("/fixture".into()),
                                    ])])
                                } else {
                                    Val::Resource(resource)
                                };
                                Ok(())
                            } else if setter {
                                results[0] = Val::Result(Ok(None));
                                Ok(())
                            } else {
                                Err(wasmtime::Error::msg(format!("unknown import: {qualified}")))
                            }
                        })
                        .map_err(|e| anyhow!("{e:#}"))?;
                }
                ComponentItem::Type(_) => {}
                _ => bail!("unexpected import item {interface_name}#{name}"),
            }
        }
    }
    Ok(linker)
}

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
    // Compiled ambient components' forbidden imports remain unresolved.
    linker
        .define_unknown_imports_as_traps(&probe_component)
        .map_err(|e| anyhow!("{e:#}"))?;
    let type_control = Component::from_file(&engine, directory.join("type-only.wasm"))
        .map_err(|e| anyhow!("{e:#}"))?;
    ambient_linker(&engine, &type_control, None, false)?
        .instantiate(&mut Store::new(&engine, ()), &type_control)
        .map_err(|e| anyhow!("inert type-only control failed: {e:#}"))?;

    for ambient in vectors["ambient_imports"].as_array().unwrap() {
        let id = ambient["id"].as_str().unwrap();
        let component = Component::from_file(
            &engine,
            directory.join("ambient").join(format!("{id}.wasm")),
        )
        .map_err(|e| anyhow!("{e:#}"))?;
        let interface_name = ambient["import"].as_str().unwrap();
        let function_name = ambient["function"].as_str().unwrap();
        let component_type = component.component_type();
        let Some(ComponentItem::ComponentInstance(interface)) = component_type
            .get_import(&engine, interface_name)
            .map(|item| item.ty)
        else {
            bail!("{id} is missing its forbidden interface");
        };
        ensure!(
            matches!(
                interface
                    .get_export(&engine, function_name)
                    .map(|item| item.ty),
                Some(ComponentItem::ComponentFunc(_))
            ),
            "{id} must import callable {interface_name}#{function_name}, not just a type"
        );
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000).map_err(|e| anyhow!("{e:#}"))?;
        let result = linker.instantiate(&mut store, &component);
        ensure!(result.is_err(), "ambient import {id} unexpectedly linked");
        let message = format!("{:#}", result.err().unwrap());
        ensure!(
            component_type
                .imports(&engine)
                .any(|(name, _)| !name.starts_with("kinetix:plugin/") && message.contains(name)),
            "{id} failed for an unrelated reason: {message}"
        );
        // All resource aliases and dependencies link. Withholding only the
        // actual operation must still fail, specifically for that function.
        let selective = ambient_linker(
            &engine,
            &component,
            Some((interface_name, function_name)),
            false,
        )?;
        let result = selective.instantiate(&mut store, &component);
        ensure!(
            result.is_err(),
            "{id} linked without its callable operation"
        );
        let message = format!("{:#}", result.err().unwrap());
        ensure!(
            message.contains(function_name),
            "{id} denial was not for its operation: {message}"
        );

        // Positive control: a fresh linker accepts the full real WASI shape,
        // then the guest must reach the exact forbidden operation's trap.
        let permissive = ambient_linker(
            &engine,
            &component,
            None,
            matches!(id, "filesystem" | "arbitrary-network"),
        )?;
        let mut permissive_store = Store::new(&engine, ());
        permissive_store
            .set_fuel(1_000_000)
            .map_err(|e| anyhow!("{e:#}"))?;
        let instance = permissive
            .instantiate(&mut permissive_store, &component)
            .map_err(|e| anyhow!("{id} positive control failed: {e:#}"))?;
        let interface = instance
            .get_export_index(&mut permissive_store, None, "health-probe")
            .context("missing health-probe interface")?;
        let index = instance
            .get_export_index(&mut permissive_store, Some(&interface), "probe")
            .context("missing probe function")?;
        let probe = instance.get_func(&mut permissive_store, index).unwrap();
        let mut results = [Val::Result(Ok(None))];
        let result = probe.call(
            &mut permissive_store,
            &[
                Val::String("fixture".into()),
                Val::String(ambient["operation"].to_string()),
            ],
            &mut results,
        );
        let error = match result {
            Err(error) => error,
            Ok(()) => bail!("{id} did not reach its host operation: {results:?}"),
        };
        ensure!(
            format!("{error:#}")
                .contains(&format!("unknown import: {interface_name}#{function_name}")),
            "{id} failed without reaching its authority-bearing operation: {error:#}"
        );
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
