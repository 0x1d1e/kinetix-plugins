use std::collections::BTreeSet;
use std::path::PathBuf;

use wit_parser::{Interface, Record, Resolve, Type, TypeDefKind, World, WorldItem, WorldKey};

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn parse_v1() -> (Resolve, wit_parser::PackageId) {
    let mut resolve = Resolve::new();
    let package = resolve
        .push_file(repo_path("wit/kinetix-plugin.wit"))
        .unwrap();
    (resolve, package)
}

fn world<'a>(resolve: &'a Resolve, package: wit_parser::PackageId, name: &str) -> &'a World {
    let world_id = *resolve.packages[package].worlds.get(name).unwrap();
    &resolve.worlds[world_id]
}

fn item_names<'a>(
    resolve: &Resolve,
    items: impl IntoIterator<Item = (&'a WorldKey, &'a WorldItem)>,
) -> BTreeSet<String> {
    items
        .into_iter()
        .map(|(key, _)| match key {
            WorldKey::Name(name) => name.clone(),
            WorldKey::Interface(id) => resolve.interfaces[*id]
                .name
                .clone()
                .expect("anonymous world interface"),
        })
        .collect()
}

fn exported_interface<'a>(resolve: &'a Resolve, world: &'a World, name: &str) -> &'a Interface {
    world
        .exports
        .iter()
        .find_map(|(key, item)| match item {
            WorldItem::Interface { id, .. }
                if match key {
                    WorldKey::Name(key_name) => key_name == name,
                    WorldKey::Interface(interface_id) => {
                        resolve.interfaces[*interface_id].name.as_deref() == Some(name)
                    }
                } =>
            {
                Some(&resolve.interfaces[*id])
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing exported interface {name}"))
}

fn record_fields(
    resolve: &Resolve,
    package: wit_parser::PackageId,
    type_name: &str,
) -> BTreeSet<String> {
    let types_id = *resolve.packages[package].interfaces.get("types").unwrap();
    let type_id = *resolve.interfaces[types_id].types.get(type_name).unwrap();
    match &resolve.types[type_id].kind {
        TypeDefKind::Record(Record { fields }) => {
            fields.iter().map(|field| field.name.clone()).collect()
        }
        other => panic!("{type_name} is not a record: {other:?}"),
    }
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn has_optional_session_param(resolve: &Resolve, interface: &Interface, function: &str) -> bool {
    let Some(function) = interface.functions.get(function) else {
        return false;
    };
    let Some(param) = function.params.iter().find(|param| param.name == "session") else {
        return false;
    };
    let Type::Id(option_id) = &param.ty else {
        return false;
    };
    matches!(
        &resolve.types[*option_id].kind,
        TypeDefKind::Option(Type::Id(context_id))
            if resolve.types[*context_id].name.as_deref() == Some("session-context")
    )
}

#[test]
fn v1_plugin_world_exposes_mechanisms_not_execution_policy() {
    let (resolve, package) = parse_v1();
    let plugin = world(&resolve, package, "plugin");
    assert_eq!(
        item_names(&resolve, plugin.exports.iter()),
        names(&[
            "credential-strategy",
            "model-source",
            "health-probe",
            "routing-facts",
            "hooks",
        ])
    );

    for (interface, operations) in [
        ("credential-strategy", &["resolve", "health", "rotate"][..]),
        ("model-source", &["discover"][..]),
        ("health-probe", &["probe"][..]),
        ("routing-facts", &["facts"][..]),
        (
            "hooks",
            &[
                "on-request-normalized",
                "on-target-candidate",
                "on-usage-finalized",
            ][..],
        ),
    ] {
        let actual: BTreeSet<_> = exported_interface(&resolve, plugin, interface)
            .functions
            .keys()
            .cloned()
            .collect();
        assert_eq!(actual, names(operations), "interface {interface}");
    }

    assert_eq!(
        record_fields(&resolve, package, "routing-fact"),
        names(&["name", "value-json", "observed-at", "max-age-ms"])
    );
    assert_eq!(
        record_fields(&resolve, package, "plugin-error"),
        names(&["code", "message", "retryable", "retry-after", "reset-at"])
    );
    assert_eq!(
        record_fields(&resolve, package, "health-observation"),
        names(&[
            "state",
            "quota-state",
            "reset-at",
            "retry-after",
            "detail-code"
        ])
    );
    assert_eq!(
        record_fields(&resolve, package, "health-observation-v2"),
        names(&[
            "state",
            "quota-state",
            "reset-at",
            "retry-after",
            "detail-code",
            "quota-snapshots",
        ])
    );
    assert_eq!(
        record_fields(&resolve, package, "credential-lease"),
        names(&["handle", "expires-at", "refresh-after", "health"])
    );
}

#[test]
fn auxiliary_worlds_expose_provider_operations_only() {
    let (resolve, package) = parse_v1();
    for (world_name, interface_name, operations) in [
        ("plugin-health-v2", "health-probe-v2", &["probe"][..]),
        ("plugin-auth", "auth-flow", &["begin", "exchange"][..]),
        (
            "plugin-model-source",
            "account-model-source",
            &["discover"][..],
        ),
    ] {
        let api = world(&resolve, package, world_name);
        assert_eq!(
            item_names(&resolve, api.exports.iter()),
            names(&[interface_name]),
            "world {world_name} exports"
        );
        let actual: BTreeSet<_> = exported_interface(&resolve, api, interface_name)
            .functions
            .keys()
            .cloned()
            .collect();
        assert_eq!(actual, names(operations), "interface {interface_name}");
    }
}

#[test]
fn legacy_adapter_world_keeps_its_v1_import_contract() {
    let (resolve, package) = parse_v1();
    let adapter = world(&resolve, package, "plugin-adapter");
    assert_eq!(
        item_names(&resolve, adapter.exports.iter()),
        names(&["provider-adapter"])
    );
    assert_eq!(
        exported_interface(&resolve, adapter, "provider-adapter")
            .functions
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        names(&[
            "wire-format",
            "build-url",
            "apply-auth",
            "build-body",
            "classify-error",
            "parse-stream-chunk",
            "parse-full-response",
        ])
    );
    // API v1 components retain this import for compatibility.
    assert!(item_names(&resolve, adapter.imports.iter()).contains("host-http"));
}

#[test]
fn v2_adapter_retains_legacy_host_imports_and_session_context() {
    let mut resolve = Resolve::new();
    let (package, _) = resolve.push_dir(repo_path("wit/v2")).unwrap();
    let adapter = world(&resolve, package, "plugin-adapter-v2");
    assert_eq!(
        item_names(&resolve, adapter.exports.iter()),
        names(&["provider-adapter"])
    );
    assert_eq!(
        item_names(&resolve, adapter.imports.iter()),
        names(&[
            "host-http",
            "host-storage",
            "host-log",
            "host-credential",
            "host-clock",
            "types",
        ]),
        "API v2 host imports are part of its compatibility contract"
    );
    let operations: BTreeSet<_> = exported_interface(&resolve, adapter, "provider-adapter")
        .functions
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        operations,
        names(&[
            "wire-format",
            "build-url",
            "apply-auth",
            "build-body",
            "classify-error",
            "parse-stream-chunk",
            "parse-full-response",
        ])
    );
    let provider = exported_interface(&resolve, adapter, "provider-adapter");
    for function in ["apply-auth", "build-body"] {
        assert!(
            has_optional_session_param(&resolve, provider, function),
            "API v2 {function} must accept optional session context"
        );
    }
}

#[test]
fn v3_adapter_is_session_aware_and_import_free() {
    let mut resolve = Resolve::new();
    let (package, _) = resolve.push_dir(repo_path("wit/v3")).unwrap();
    let adapter = world(&resolve, package, "plugin-adapter-v3");
    assert_eq!(
        item_names(&resolve, adapter.exports.iter()),
        names(&["provider-adapter"])
    );
    assert!(
        item_names(&resolve, adapter.imports.iter())
            .iter()
            .all(|name| !name.starts_with("host-")),
        "v3 adapter must not import host capabilities"
    );
    let operations: BTreeSet<_> = exported_interface(&resolve, adapter, "provider-adapter")
        .functions
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        operations,
        names(&[
            "wire-format",
            "build-url",
            "apply-auth",
            "build-body",
            "classify-error",
            "parse-stream-chunk",
            "parse-full-response",
        ])
    );
    let provider = exported_interface(&resolve, adapter, "provider-adapter");
    for function in ["apply-auth", "build-body"] {
        assert!(
            has_optional_session_param(&resolve, provider, function),
            "API v3 {function} must accept optional session context"
        );
    }
}
