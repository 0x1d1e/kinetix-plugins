# Ambient probe WIT

`deps/{cli,clocks,filesystem,http,io,random,sockets}` is vendored from [WebAssembly/wasi-http v0.2.0](https://github.com/WebAssembly/wasi-http/tree/2c64dc93da95e2790ad531761706ec655d0a936f/wit), commit `2c64dc93da95e2790ad531761706ec655d0a936f`. HTTP files come from `wit/`; other packages come from `wit/deps/`. Only trailing whitespace is normalized. Fixture builds are offline and use these pinned interface definitions.

Each world in `ambient.wit` includes the canonical plugin world from `../../wit` through wit-bindgen's multi-path resolver, plus only its probe's required interfaces. `deps/ambient` defines the two non-WASI forbidden operations. Ambient Cargo features are mutually exclusive: each fixture build selects one probe and its matching minimal world. The component smoke test pins each compiled fixture's exact non-contract import set, including type dependencies.
