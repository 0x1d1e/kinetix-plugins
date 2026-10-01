#!/usr/bin/env python3
"""Validate plugin.toml against the canonical v1 manifest schema."""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import re
import sys
import tomllib
import urllib.parse

from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas/plugin-manifest-v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def require(condition: bool, path: pathlib.Path, message: str) -> None:
    if not condition:
        raise ValueError(f"{path}: {message}")


def validate_semver_component_bounds(path: pathlib.Path, data: dict) -> None:
    versions = [("version", data["version"])]
    compatibility = data.get("compatibility", {})
    versions.extend(
        (f"compatibility.{key}", value)
        for key, value in compatibility.items()
        if value is not None
    )
    for label, version in versions:
        core = version.split("+", 1)[0].split("-", 1)[0]
        for component in core.split("."):
            require(
                len(component) < 20
                or (len(component) == 20 and component <= "18446744073709551615"),
                path,
                f"{label} component exceeds the host SemVer u64 range",
            )


def _semver_precedence(version: str) -> tuple:
    without_build = version.split("+", 1)[0]
    core, separator, prerelease = without_build.partition("-")
    core_parts = tuple(int(part) for part in core.split("."))
    if not separator:
        return core_parts, 1, ()
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in prerelease.split(".")
    )
    return core_parts, 0, identifiers


def validate_byte_size(path: pathlib.Path, field: str, value: str) -> None:
    units = {
        "GiB": 1024**3,
        "MiB": 1024**2,
        "KiB": 1024,
        "GB": 1_000_000_000,
        "MB": 1_000_000,
        "KB": 1_000,
        "B": 1,
    }
    size = value.strip()
    multiplier = 1
    for suffix, factor in units.items():
        if size.endswith(suffix):
            size = size[: -len(suffix)].strip()
            multiplier = factor
            break
    require(re.fullmatch(r"\+?[0-9]+", size) is not None, path, f"limits.{field} is not a valid byte size")
    require(int(size) <= (2**64 - 1) // multiplier, path, f"limits.{field} exceeds the host u64 byte-size range")


def validate_network_host(path: pathlib.Path, value: str) -> None:
    host = value.strip()
    require(bool(host), path, "network host must not be empty")
    require(host != "*" and ("*" not in host or host.startswith("*.")), path, f"network host {host!r} has an invalid wildcard")
    base = host[2:] if host.startswith("*.") else host
    require("*" not in base and bool(base) and "/" not in base and " " not in base, path, f"network host {host!r} is invalid")
    try:
        ipaddress.ip_address(base)
    except ValueError:
        pass
    else:
        raise ValueError(f"{path}: network host {host!r}: IP literals are not allowed; declare a hostname")


def validate_connection_parameters(path: pathlib.Path, provider: dict, hosts: list[str]) -> None:
    parameters = provider.get("parameters", {})
    templates = (provider["base_url"], provider.get("models_path", ""))
    if not parameters:
        require(not any("{" in value or "}" in value for value in templates), path, "integration URL templates require declared parameters")
        return
    require(bool(hosts) and len(hosts) <= 64, path, "parameterized integration requires 1..=64 declared network_hosts")
    for name, parameter in parameters.items():
        require(parameter["min_length"] <= parameter["max_length"], path, f"invalid connection parameter declaration {name!r}")
    parsed = urllib.parse.urlsplit(provider["base_url"])
    require(not parsed.query and not parsed.fragment and "?" not in provider["base_url"] and "#" not in provider["base_url"], path, "connection base_url may not contain query or fragment")
    remainder = provider["base_url"].split("://", 1)[1]
    authority, _, base_path = remainder.partition("/")
    require(not any(character in authority for character in "{}%"), path, "connection parameters are permitted only in URL path segments")
    models_path = provider.get("models_path")
    if models_path is not None:
        require(models_path.startswith("/") and not models_path.startswith("//"), path, "connection models_path must be an absolute path")
    for template_path in (base_path, models_path or ""):
        require(len(template_path.encode("utf-8")) <= 4096 and not any(character in template_path for character in "%\\\\?#"), path, "connection path contains forbidden encoding or delimiters")
        for segment in template_path.split("/"):
            require(segment not in (".", ".."), path, "connection path must not contain traversal segments")
            if "{" in segment or "}" in segment:
                match = re.fullmatch(r"\{([^{}]+)\}", segment)
                if match is None:
                    raise ValueError(f"{path}: connection template variables must occupy a complete path segment")
                require(match[1] in parameters, path, f"undeclared connection parameter {match[1]!r}")
    for host in hosts:
        require(not any(character in host for character in "/:{}% ?#"), path, "invalid connection network host")
    hostname = parsed.hostname or ""
    def matches(pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if not hostname.endswith(suffix):
                return False
            prefix = hostname[:-len(suffix)].removesuffix(".")
            return bool(prefix) and "." not in prefix
        return pattern == hostname
    require(any(matches(host) for host in hosts), path, "connection destination is outside declared network_hosts")


def validate_provider_template(path: pathlib.Path, integration: dict, permissions: dict) -> None:
    provider = integration.get("provider")
    if provider is None:
        return
    label = f"integration {integration['id']} provider"
    base_url = provider["base_url"]
    try:
        parsed = urllib.parse.urlsplit(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise ValueError(f"{path}: {label} base_url is invalid: {error}") from error
    require(parsed.scheme.lower() == "https", path, f"{label} base_url must use https")
    require(hostname is not None, path, f"{label} base_url has no host")
    require(parsed.username in (None, "") and parsed.password is None, path, f"{label} base_url may not contain userinfo")
    require(not any(character.isspace() for character in hostname), path, f"{label} base_url has an invalid host")
    try:
        hostname.encode("idna")
    except UnicodeError as error:
        raise ValueError(f"{path}: {label} base_url has an invalid host: {error}") from error

    validate_connection_parameters(path, provider, permissions.get("network_hosts", []))
    wire_format = provider.get("wire_format", "plugin")
    adapter = integration.get("provider_adapter")
    require(not adapter or wire_format == "plugin", path, f"integration {integration['id']} provider_adapter requires wire_format 'plugin'")
    require(wire_format != "plugin" or bool(adapter), path, f"integration {integration['id']} provider wire_format 'plugin' requires provider_adapter")
    protocols = integration.get("protocols")
    if protocols is not None:
        compatible = {
            "openai-chat": "openai",
            "openai-responses": "openai",
            "anthropic": "anthropic",
            "gemini": "gemini",
            "plugin-native": "plugin",
        }
        for protocol in protocols["upstream"]:
            require(compatible[protocol] == wire_format, path, f"integration {integration['id']} upstream protocol {protocol!r} is incompatible with provider wire_format {wire_format!r}")

    auth_scheme = provider.get("auth_scheme", "bearer")
    if auth_scheme == "none":
        mode = integration.get("credential_mode")
        no_auth = mode == "none" or (mode is None and not permissions.get("credential_read", False) and not permissions.get("credential_scopes"))
        auth_headers = {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"}
        require(no_auth and not integration.get("auth_flow") and not integration.get("credential_strategy") and "custom_header_name" not in provider and "custom_param_name" not in provider and not any(name.lower() in auth_headers for name in provider.get("extra_headers", {})), path, f"{label}: no-auth provider must use credential_mode 'none' without credential bindings or auth fields")
    elif auth_scheme == "custom_header":
        require(bool(provider.get("custom_header_name", "").strip()), path, f"{label} custom_header auth requires custom_header_name")
    elif auth_scheme == "query_param":
        require(bool(provider.get("custom_param_name", "").strip()), path, f"{label} query_param auth requires custom_param_name")
    if provider.get("models_path") is not None:
        models_path = provider["models_path"]
        require(models_path.startswith("/") and "://" not in models_path, path, f"{label} models_path must be an absolute URL path")
    for host in provider.get("credential_hosts", []):
        require(bool(host.strip()) and not any(character in host for character in "/:* "), path, f"{label} credential host {host!r} is invalid")
    for name, value in provider.get("extra_headers", {}).items():
        require(bool(name.strip()) and not any(character in name for character in "\r\n:") and not any(character in value for character in "\r\n"), path, f"{label} contains an invalid extra header")


def validate_source_semantics(path: pathlib.Path, data: dict) -> None:
    require(bool(data["name"].strip()), path, "manifest name must not be empty")
    plugin_id = data["id"]
    require(not plugin_id.startswith(".") and not plugin_id.endswith(".") and ".." not in plugin_id, path, "id has invalid dot placement")

    compatibility = data.get("compatibility", {})
    minimum = compatibility.get("min_host_version")
    maximum = compatibility.get("max_host_version")
    if minimum is not None and maximum is not None:
        require(_semver_precedence(minimum) <= _semver_precedence(maximum), path, "compatibility.min_host_version must not exceed max_host_version")

    for field in ("memory", "max_http_body", "storage"):
        if field in data.get("limits", {}):
            validate_byte_size(path, field, data["limits"][field])

    provides = data.get("provides", {})
    permissions = data.get("permissions", {})
    capability_keys = (
        "credential_strategies", "auth_flows", "model_sources", "account_model_sources",
        "provider_adapters", "health_probes", "routing_facts", "hooks",
    )
    require(any(provides.get(key) for key in capability_keys) or any(integration.get("provider") for integration in data.get("integrations", [])), path, "manifest provides no capabilities or provider integrations")
    require(not provides.get("thinking_translation") or bool(provides.get("provider_adapters")), path, "provides.thinking_translation requires at least one provider_adapter")
    allowed_hooks = {"on_request_normalized", "on_target_candidate", "on_usage_finalized"}
    require(set(provides.get("hooks", [])) <= allowed_hooks, path, "provides.hooks contains an unknown hook")

    provided = {key: set(provides.get(key, [])) for key in capability_keys}
    integration_ids: set[str] = set()
    for integration in data.get("integrations", []):
        integration_id = integration["id"]
        require(integration_id not in integration_ids, path, f"duplicate integration id {integration_id}")
        integration_ids.add(integration_id)
        require(bool(integration["name"].strip()), path, f"integration {integration_id} name must not be empty")

        features = integration.get("features")
        protocols = integration.get("protocols")
        require((features is None) == (protocols is None), path, "integrations.features and integrations.protocols must be declared together")
        if features is not None:
            require(not features["parallel_tools"] or features["tools"], path, "parallel_tools requires tools")
            require(features["model_discovery"] == bool(integration.get("model_source")), path, f"integration {integration_id}: model_discovery must match model_source")

        bindings = {
            "provider_adapter": "provider_adapters",
            "credential_strategy": "credential_strategies",
            "auth_flow": "auth_flows",
        }
        require(any(integration.get(key) for key in (*bindings, "model_source", "provider")), path, f"integration {integration_id} must reference at least one provided capability or provider template")
        for field, provided_key in bindings.items():
            name = integration.get(field)
            if name:
                require(name in provided[provided_key], path, f"integration {integration_id} references unprovided {field} {name}")
        model_source = integration.get("model_source")
        if model_source:
            legacy = model_source in provided["model_sources"]
            account = model_source in provided["account_model_sources"]
            require(legacy or account, path, f"integration {integration_id} references unprovided model_source {model_source}")
            require(not (legacy and account), path, f"integration {integration_id} model_source {model_source!r} is declared as both legacy and account-aware")

        mode = integration.get("credential_mode")
        manual = integration.get("manual_credential")
        require(manual is None or mode == "manual", path, f"integration {integration_id}: manual_credential requires explicit manual credential mode")
        if mode == "auth_flow":
            require(bool(integration.get("auth_flow")) and bool(integration.get("credential_strategy")), path, f"integration {integration_id}: auth_flow credential mode requires auth_flow and credential_strategy")
        elif mode == "none":
            require(not integration.get("auth_flow") and not integration.get("credential_strategy"), path, f"integration {integration_id}: none credential mode cannot declare auth_flow or credential_strategy")
        elif mode == "manual":
            require(not integration.get("auth_flow"), path, f"integration {integration_id}: manual credential mode cannot declare auth_flow")

        install = integration.get("install")
        if install is not None:
            require(mode is not None, path, f"integration {integration_id}: install requires explicit credential_mode")
            require(integration.get("provider") is not None, path, f"integration {integration_id}: install requires a provider template")
            require(mode != "manual" or manual is not None, path, f"integration {integration_id}: manual install requires manual_credential kind and requirements")
            account = install.get("account")
            require(account is None or mode != "none", path, f"integration {integration_id}: none credential mode cannot propose an account or credential")
            if account is not None:
                require(bool(account["name"].strip()), path, f"integration {integration_id}: account name must not be empty")
            route_ids: set[str] = set()
            for route in install.get("routes", []):
                require(route["id"] not in route_ids, path, f"integration {integration_id}: duplicate install route id {route['id']}")
                route_ids.add(route["id"])
                require(bool(route["model"].strip()), path, f"integration {integration_id}: route model must not be empty")

        validate_provider_template(path, integration, permissions)

    ui = data.get("ui", {})
    setting_keys: set[str] = set()
    for setting in ui.get("settings", []):
        key = setting["key"]
        require(key not in setting_keys, path, f"duplicate ui setting key {key}")
        setting_keys.add(key)
        require(bool(setting["label"].strip()), path, f"ui setting {key!r} label must not be empty")
        options = setting.get("options", [])
        require(setting["kind"] == "select" or not options, path, f"ui setting {key!r} options are only valid for select settings")
        if setting["kind"] == "select":
            require(bool(options), path, f"select ui setting {key!r} requires options")
            require(all(options), path, f"ui setting {key!r} has an empty option")
            if "default" in setting:
                require(setting["default"] in options, path, f"ui setting {key!r} default is not in options")
        if setting["kind"] == "boolean" and "default" in setting:
            require(setting["default"] in ("true", "false"), path, f"boolean ui setting {key!r} default must be 'true' or 'false'")
        require(setting["kind"] != "secret" or "default" not in setting, path, f"secret ui setting {key!r} may not declare a default")

    action_ids: set[str] = set()
    for action in ui.get("actions", []):
        action_id = action["id"]
        require(action_id not in action_ids, path, f"duplicate ui action id {action_id}")
        action_ids.add(action_id)
        require(bool(action["label"].strip()), path, f"ui action {action_id!r} label must not be empty")
        integration = next((item for item in data.get("integrations", []) if item["id"] == action["integration"]), None)
        if integration is None:
            raise ValueError(f"{path}: ui action {action_id!r} references unknown integration {action['integration']!r}")
        require(bool(integration.get("auth_flow")) and bool(integration.get("credential_strategy")), path, f"auth ui action {action_id!r} requires integration {integration['id']!r} to declare auth_flow and credential_strategy")

    network_hosts: set[str] = set()
    for host in permissions.get("network_hosts", []):
        validate_network_host(path, host)
        require(host not in network_hosts, path, f"duplicate network_hosts entry {host!r}")
        network_hosts.add(host)

    credential_scopes: set[str] = set()
    for scope in permissions.get("credential_scopes", []):
        require(scope not in credential_scopes, path, f"duplicate credential_scopes entry {scope!r}")
        credential_scopes.add(scope)
        if scope == "*":
            continue
        if scope.startswith("provider:"):
            require(bool(scope.removeprefix("provider:").strip()), path, "credential scope 'provider:' requires a provider id")
        elif scope.startswith("credential_strategy:"):
            strategy = scope.removeprefix("credential_strategy:")
            require(strategy in provided["credential_strategies"], path, f"credential scope {scope!r} references a credential strategy this plugin does not provide")
        else:
            raise ValueError(f"{path}: invalid credential scope {scope!r}: expected '*', 'provider:<id>', or 'credential_strategy:<name>'")

    if provides.get("routing_facts"):
        mode = data.get("routing_facts_mode", "pure")
        require(mode in ("pure", "cached"), path, f"invalid routing_facts_mode {mode!r}: expected 'pure' or 'cached'")
        if mode == "cached":
            refresh = data.get("routing_facts_refresh_ms", 30_000)
            require(5_000 <= refresh <= 3_600_000, path, "routing_facts_refresh_ms must be 5000..=3600000 for cached routing facts")


def validate_manifest(path: pathlib.Path, data: dict) -> str:
    errors = sorted(VALIDATOR.iter_errors(data), key=lambda error: list(map(str, error.absolute_path)))
    if errors:
        error = errors[0]
        location = ".".join(map(str, error.absolute_path)) or "manifest"
        raise ValueError(f"{path}: {location}: {error.message}")

    validate_semver_component_bounds(path, data)
    validate_source_semantics(path, data)
    return data["id"]


def validate_plugin_directory(plugin_dir: pathlib.Path) -> tuple[str, str, str]:
    manifest_path = plugin_dir / "plugin.toml"
    cargo_path = plugin_dir / "Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
        plugin_id = validate_manifest(manifest_path, manifest)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        raise ValueError(f"{plugin_dir}: {error}") from error

    package = cargo.get("package")
    if not isinstance(package, dict):
        raise ValueError(f"{cargo_path}: [package] table is required")
    crate_version = package.get("version")
    require(isinstance(crate_version, str), cargo_path, "[package].version must be a string")
    manifest_version = manifest["version"]
    require(
        crate_version == manifest_version,
        manifest_path,
        f"plugin.toml version ({manifest_version}) does not match Cargo.toml version ({crate_version})",
    )
    return plugin_id, manifest_version, package.get("name", "")


def validate_directory(root: pathlib.Path) -> int:
    manifests = sorted((root / "plugins").glob("*/plugin.toml"))
    if not manifests:
        raise ValueError(f"{root}: no plugin manifests found")
    ids = set()
    for manifest_path in manifests:
        plugin_id, _, _ = validate_plugin_directory(manifest_path.parent)
        require(plugin_id not in ids, manifest_path, f"duplicate plugin id {plugin_id}")
        ids.add(plugin_id)
    return len(manifests)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root")
    parser.add_argument("--plugin-dir", type=pathlib.Path, help="validate one plugin directory")
    parser.add_argument("--print-fields", action="store_true", help="print id, version, and crate name as TSV")
    args = parser.parse_args()

    try:
        if args.plugin_dir:
            plugin_id, version, crate_name = validate_plugin_directory(args.plugin_dir)
            if args.print_fields:
                print(f"{plugin_id}\t{version}\t{crate_name}")
            else:
                print(f"validated {plugin_id} {version}")
        else:
            count = validate_directory(args.root)
            print(f"validated {count} plugin manifest(s)")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
