#[test]
fn sdk_wit_matches_the_canonical_abi() {
    assert_eq!(
        include_str!("../wit/kinetix-plugin.wit"),
        include_str!("../../wit/kinetix-plugin.wit")
    );
}
