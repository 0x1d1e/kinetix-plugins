//! Runs the compiled component through the shared account-model-source suite.
#[test]
fn shared_discovery_conformance_fixtures() {
    kinetix_discovery_conformance::check(
        env!("CARGO_PKG_NAME"),
        include_str!("../discovery-conformance.json"),
    );
}
