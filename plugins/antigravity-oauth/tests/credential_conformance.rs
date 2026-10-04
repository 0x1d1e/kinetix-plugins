//! Runs the compiled component through the shared credential-strategy suite.
#[test]
fn shared_credential_conformance_fixtures() {
    kinetix_credential_conformance::check(
        env!("CARGO_PKG_NAME"),
        include_str!("../credential-conformance.json"),
    );
}
