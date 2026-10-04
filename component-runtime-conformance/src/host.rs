use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
};
use wasmtime::{
    component::{types::ComponentItem, Component, Instance, Linker, Val},
    Engine, Store,
};

/// A guest `plugin-error`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after: Option<u64>,
    pub reset_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// What the scripted host returns for the next `host-http.send`.
#[derive(Clone, Debug)]
pub enum HttpOutcome {
    Response(HttpResponse),
    Failure(WireError),
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The `credential-ref` the guest asked the host to inject, as JSON.
    pub credential: Option<Value>,
}

/// Mutable host world. A fresh one per case keeps cases independent.
#[derive(Default)]
pub struct HostState {
    pub now_ms: u64,
    pub storage: BTreeMap<String, Vec<u8>>,
    /// Plaintext returned by `host-credential.read`; `None` makes it fail.
    pub credential: Option<String>,
    pub http: VecDeque<HttpOutcome>,
    pub requests: Vec<HttpRequest>,
    /// The `credential-ref` of every `host-credential.read`, as JSON.
    pub credential_reads: Vec<Value>,
}

pub enum Outcome {
    Ok(Value),
    Err(WireError),
}

/// Build the JSON form of an `account-ref` argument.
pub fn account_ref(provider_id: &str, account_id: &str) -> Val {
    Val::Record(vec![
        ("provider-id".into(), Val::String(provider_id.into())),
        ("account-id".into(), Val::String(account_id.into())),
    ])
}

/// An instantiated plugin component bound to a scripted host.
pub struct Guest {
    store: Store<HostState>,
    instance: Instance,
}

impl Guest {
    pub fn instantiate(component: &Path, host: HostState) -> Result<Self> {
        let engine = Engine::default();
        let component = Component::from_file(&engine, component)
            .map_err(|error| anyhow!("load component {}: {error}", component.display()))?;
        let linker = host_linker(&engine, &component)?;
        let mut store = Store::new(&engine, host);
        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|error| anyhow!("instantiate component: {error}"))?;
        Ok(Self { store, instance })
    }

    pub fn host(&self) -> &HostState {
        self.store.data()
    }

    pub fn host_mut(&mut self) -> &mut HostState {
        self.store.data_mut()
    }

    /// Call `interface#func` and classify the guest's `result<_, plugin-error>`.
    /// A trap, including an unscripted host call, is an `Err`.
    pub fn call(&mut self, interface: &str, func: &str, params: &[Val]) -> Result<Outcome> {
        let interface_index = self
            .instance
            .get_export_index(&mut self.store, None, interface)
            .with_context(|| format!("component does not export {interface}"))?;
        let func_index = self
            .instance
            .get_export_index(&mut self.store, Some(&interface_index), func)
            .with_context(|| format!("{interface} does not export {func}"))?;
        let function = self
            .instance
            .get_func(&mut self.store, func_index)
            .with_context(|| format!("{interface}#{func} is not a function"))?;
        let mut results = [Val::Bool(false)];
        function
            .call(&mut self.store, params, &mut results)
            .map_err(|error| anyhow!("{interface}#{func} trapped: {error:#}"))?;
        match &results[0] {
            Val::Result(Ok(value)) => Ok(Outcome::Ok(
                value.as_deref().map(val_to_json).unwrap_or(Value::Null),
            )),
            Val::Result(Err(Some(error))) => Ok(Outcome::Err(wire_error(error)?)),
            other => bail!("{interface}#{func} returned a non-result: {other:?}"),
        }
    }
}

fn snake(name: &str) -> String {
    name.replace('-', "_")
}

/// Render a component value as JSON with snake_case record keys.
pub fn val_to_json(value: &Val) -> Value {
    match value {
        Val::Bool(v) => json!(v),
        Val::S8(v) => json!(v),
        Val::U8(v) => json!(v),
        Val::S16(v) => json!(v),
        Val::U16(v) => json!(v),
        Val::S32(v) => json!(v),
        Val::U32(v) => json!(v),
        Val::S64(v) => json!(v),
        Val::U64(v) => json!(v),
        Val::Float32(v) => json!(v),
        Val::Float64(v) => json!(v),
        Val::Char(v) => json!(v.to_string()),
        Val::String(v) => json!(v),
        Val::List(items) | Val::Tuple(items) => {
            Value::Array(items.iter().map(val_to_json).collect())
        }
        Val::Record(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| (snake(name), val_to_json(value)))
                .collect(),
        ),
        Val::Variant(name, payload) => match payload {
            Some(payload) => json!({ snake(name): val_to_json(payload) }),
            None => json!(snake(name)),
        },
        Val::Enum(name) => json!(snake(name)),
        Val::Option(inner) => inner.as_deref().map(val_to_json).unwrap_or(Value::Null),
        Val::Result(Ok(inner)) => json!({"ok": inner.as_deref().map(val_to_json)}),
        Val::Result(Err(inner)) => json!({"err": inner.as_deref().map(val_to_json)}),
        other => json!(format!("{other:?}")),
    }
}

fn field<'a>(fields: &'a [(String, Val)], name: &str) -> Result<&'a Val> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value)
        .with_context(|| format!("record is missing field {name}"))
}

fn string(value: &Val) -> Result<String> {
    match value {
        Val::String(value) => Ok(value.clone()),
        other => bail!("expected string, got {other:?}"),
    }
}

fn optional(value: &Val) -> Result<Option<&Val>> {
    match value {
        Val::Option(inner) => Ok(inner.as_deref()),
        other => bail!("expected option, got {other:?}"),
    }
}

fn pairs(value: &Val) -> Result<Vec<(String, String)>> {
    let Val::List(items) = value else {
        bail!("expected list of tuples, got {value:?}");
    };
    items
        .iter()
        .map(|item| match item {
            Val::Tuple(pair) if pair.len() == 2 => Ok((string(&pair[0])?, string(&pair[1])?)),
            other => bail!("expected string tuple, got {other:?}"),
        })
        .collect()
}

fn bytes(value: &Val) -> Result<Vec<u8>> {
    let Val::List(items) = value else {
        bail!("expected list<u8>, got {value:?}");
    };
    items
        .iter()
        .map(|item| match item {
            Val::U8(byte) => Ok(*byte),
            other => bail!("expected u8, got {other:?}"),
        })
        .collect()
}

fn wire_error(value: &Val) -> Result<WireError> {
    let Val::Record(fields) = value else {
        bail!("expected plugin-error record, got {value:?}");
    };
    Ok(WireError {
        code: string(field(fields, "code")?)?,
        message: string(field(fields, "message")?)?,
        retryable: matches!(field(fields, "retryable")?, Val::Bool(true)),
        retry_after: match optional(field(fields, "retry-after")?)? {
            Some(Val::U64(seconds)) => Some(*seconds),
            _ => None,
        },
        reset_at: optional(field(fields, "reset-at")?)?
            .map(string)
            .transpose()?,
    })
}

fn error_val(error: &WireError) -> Val {
    Val::Record(vec![
        ("code".into(), Val::String(error.code.clone())),
        ("message".into(), Val::String(error.message.clone())),
        ("retryable".into(), Val::Bool(error.retryable)),
        (
            "retry-after".into(),
            Val::Option(error.retry_after.map(|v| Box::new(Val::U64(v)))),
        ),
        (
            "reset-at".into(),
            Val::Option(error.reset_at.clone().map(|v| Box::new(Val::String(v)))),
        ),
    ])
}

fn byte_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().copied().map(Val::U8).collect())
}

fn host_failure(code: &str, message: String) -> Val {
    Val::Result(Err(Some(Box::new(error_val(&WireError {
        code: code.into(),
        message,
        retryable: false,
        retry_after: None,
        reset_at: None,
    })))))
}

fn http_request(value: &Val) -> Result<HttpRequest> {
    let Val::Record(fields) = value else {
        bail!("expected http-request record, got {value:?}");
    };
    Ok(HttpRequest {
        method: string(field(fields, "method")?)?,
        url: string(field(fields, "url")?)?,
        headers: pairs(field(fields, "headers")?)?,
        body: bytes(field(fields, "body")?)?,
        credential: optional(field(fields, "credential")?)?.map(val_to_json),
    })
}

fn http_send(state: &mut HostState, params: &[Val]) -> Result<Val> {
    let request = http_request(params.first().context("host-http.send without a request")?)?;
    let url = request.url.clone();
    state.requests.push(request);
    let outcome = state
        .http
        .pop_front()
        .ok_or_else(|| anyhow!("unscripted HTTP request to {url}"))?;
    Ok(match outcome {
        HttpOutcome::Response(response) => Val::Result(Ok(Some(Box::new(Val::Record(vec![
            ("status".into(), Val::U16(response.status)),
            (
                "headers".into(),
                Val::List(
                    response
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            Val::Tuple(vec![Val::String(k.clone()), Val::String(v.clone())])
                        })
                        .collect(),
                ),
            ),
            ("body".into(), byte_list(&response.body)),
            ("body-truncated".into(), Val::Bool(response.truncated)),
        ]))))),
        HttpOutcome::Failure(error) => Val::Result(Err(Some(Box::new(error_val(&error))))),
    })
}

fn call_host(
    state: &mut HostState,
    interface: &str,
    name: &str,
    params: &[Val],
) -> Result<Option<Val>> {
    let family = interface.split('@').next().unwrap_or(interface);
    Ok(Some(match (family, name) {
        ("kinetix:plugin/host-http", "send") => http_send(state, params)?,
        ("kinetix:plugin/host-clock", "now-unix-millis") => Val::U64(state.now_ms),
        ("kinetix:plugin/host-clock", "now-unix-seconds") => Val::U64(state.now_ms / 1000),
        ("kinetix:plugin/host-storage", "get") => Val::Option(
            state
                .storage
                .get(&string(&params[0])?)
                .map(|value| Box::new(byte_list(value))),
        ),
        ("kinetix:plugin/host-storage", "put") => {
            state
                .storage
                .insert(string(&params[0])?, bytes(&params[1])?);
            Val::Result(Ok(None))
        }
        ("kinetix:plugin/host-storage", "delete") => {
            state.storage.remove(&string(&params[0])?);
            Val::Result(Ok(None))
        }
        ("kinetix:plugin/host-log", "log") => return Ok(None),
        ("kinetix:plugin/host-credential", "read") => {
            state.credential_reads.push(val_to_json(
                params.first().context("credential read without a ref")?,
            ));
            match &state.credential {
                Some(raw) => Val::Result(Ok(Some(Box::new(Val::String(raw.clone()))))),
                None => host_failure("credential_unavailable", "no credential".into()),
            }
        }
        _ => bail!("host capability {interface}#{name} is not available to this conformance suite"),
    }))
}

fn host_linker(engine: &Engine, component: &Component) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    for (interface_name, import) in component.component_type().imports(engine) {
        let ComponentItem::ComponentInstance(interface) = import.ty else {
            bail!("unexpected non-interface import {interface_name}");
        };
        let mut instance = linker
            .instance(interface_name)
            .map_err(|error| anyhow!("{error:#}"))?;
        for (name, export) in interface.exports(engine) {
            match export.ty {
                ComponentItem::ComponentFunc(_) => {
                    let qualified = interface_name.to_string();
                    let func = name.to_string();
                    instance
                        .func_new(name, move |mut store, _, params, results| {
                            let value = call_host(store.data_mut(), &qualified, &func, params)
                                .map_err(|error| wasmtime::Error::msg(format!("{error:#}")))?;
                            if let Some(value) = value {
                                results[0] = value;
                            }
                            Ok(())
                        })
                        .map_err(|error| anyhow!("{error:#}"))?;
                }
                ComponentItem::Type(_) => {}
                _ => bail!("unexpected import item {interface_name}#{name}"),
            }
        }
    }
    Ok(linker)
}

/// Build a scripted `host-http` outcome from fixture JSON: either
/// `{failure: {code, message?, retryable?, retry_after?}}` or
/// `{status, json | text | hex, truncated?}`.
pub fn http_outcome(spec: &Value) -> Result<HttpOutcome> {
    if let Some(failure) = spec.get("failure") {
        return Ok(HttpOutcome::Failure(WireError {
            code: failure["code"].as_str().context("failure code")?.into(),
            message: failure["message"].as_str().unwrap_or("").into(),
            retryable: failure["retryable"].as_bool().unwrap_or(false),
            retry_after: failure["retry_after"].as_u64(),
            reset_at: None,
        }));
    }
    let body = if let Some(json) = spec.get("json") {
        json.to_string().into_bytes()
    } else if let Some(text) = spec.get("text") {
        text.as_str().context("text body")?.as_bytes().to_vec()
    } else if let Some(hex) = spec.get("hex") {
        let hex = hex.as_str().context("hex body")?;
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    Ok(HttpOutcome::Response(HttpResponse {
        status: spec["status"].as_u64().context("status")? as u16,
        headers: Vec::new(),
        body,
        truncated: spec["truncated"].as_bool().unwrap_or(false),
    }))
}
