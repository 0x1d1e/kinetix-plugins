# Ambient probe WIT

`deps/{cli,clocks,filesystem,http,io,random,sockets}` is vendored from [WebAssembly/wasi-http v0.2.0](https://github.com/WebAssembly/wasi-http/tree/2c64dc93da95e2790ad531761706ec655d0a936f/wit), commit `2c64dc93da95e2790ad531761706ec655d0a936f`. HTTP files come from `wit/`; other packages come from `wit/deps/`. Only trailing whitespace is normalized. Fixture builds are offline and use these pinned interface definitions.

`ambient.wit` includes the canonical plugin world from `../../wit` through wit-bindgen's multi-path resolver. `deps/ambient` defines the two non-WASI forbidden operations. Each Cargo feature selects one callable probe; unused WASI imports are eliminated when constructing its component.
