use anyhow::{anyhow, bail, ensure, Context, Result};
use wasmtime::{
    component::{Component, Linker, Val},
    Engine, Store,
};

const TEST_NOW_UNIX_MILLIS: u64 = 1_700_000_000_123;
const TEST_PROJECT_ID: &str = "core-owned-project";

fn main() -> Result<()> {
    let component_path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: adapter-runtime-conformance <component.wasm>"))?;
    let engine = Engine::default();
    let component = Component::from_file(&engine, &component_path)
        .map_err(|error| anyhow!("load component {component_path}: {error}"))?;

    // Every unresolved host import traps if called. The production component
    // also exports v1 worlds that import host storage, but the v2 adapter call
    // must complete without invoking any host capability.
    let mut linker = Linker::<()>::new(&engine);
    linker
        .define_unknown_imports_as_traps(&component)
        .map_err(|error| anyhow!("define trapping host imports: {error}"))?;
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &component)
        .map_err(|error| anyhow!("instantiate component: {error}"))?;

    let adapter = instance
        .get_export_index(&mut store, None, "kinetix:plugin/provider-adapter@2.0.0")
        .context("component is missing the v2 provider-adapter export")?;
    let build_body_index = instance
        .get_export_index(&mut store, Some(&adapter), "build-body")
        .context("v2 provider-adapter is missing build-body")?;
    let build_body = instance
        .get_func(&mut store, build_body_index)
        .context("v2 build-body export is not a function")?;

    let request = r#"{"schema":"kinetix.plugin.request","schema_version":1,"messages":[]}"#;
    let provider = serde_json::json!({
        "id": "antigravity",
        "_kinetix": {
            "account_id": "runtime-test-account",
            "project_id": TEST_PROJECT_ID,
            "now_unix_millis": TEST_NOW_UNIX_MILLIS,
        }
    })
    .to_string();
    let model = r#"{"upstream_id":"gemini-3-flash"}"#;
    let params = [
        Val::String(request.into()),
        Val::String(provider),
        Val::String(model.into()),
        Val::Option(None),
    ];
    let mut results = [Val::Result(Ok(None))];
    build_body
        .call(&mut store, &params, &mut results)
        .map_err(|error| anyhow!("v2 build-body called a host capability or trapped: {error}"))?;

    let body = match &results[0] {
        Val::Result(Ok(Some(body))) => match body.as_ref() {
            Val::String(body) => body,
            other => bail!("build-body returned a non-string body: {other:?}"),
        },
        Val::Result(Err(Some(error))) => bail!("build-body returned an error: {error:?}"),
        other => bail!("unexpected build-body result: {other:?}"),
    };
    let body: serde_json::Value = serde_json::from_str(body).context("body is invalid JSON")?;
    ensure!(
        body.get("project").and_then(serde_json::Value::as_str) == Some(TEST_PROJECT_ID),
        "adapter did not translate the core-owned project_id context"
    );
    ensure!(
        body.get("requestId")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| id.contains(&format!("/{TEST_NOW_UNIX_MILLIS}/"))),
        "adapter did not use the core-owned now_unix_millis context"
    );

    println!("v2 build-body completed with every host import trapping");
    Ok(())
}
