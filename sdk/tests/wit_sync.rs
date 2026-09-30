#[test]
fn all_v1_wit_copies_match_the_canonical_abi() {
    let canonical = include_str!("../../wit/kinetix-plugin.wit");
    assert_eq!(include_str!("../wit/kinetix-plugin.wit"), canonical);
    assert_eq!(
        include_str!("../../wit/v2/deps/kinetix-plugin/kinetix-plugin.wit"),
        canonical
    );
    assert_eq!(
        include_str!("../wit-v2/deps/kinetix-plugin/kinetix-plugin.wit"),
        canonical
    );
}
