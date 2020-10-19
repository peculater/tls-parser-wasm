# tls_parser WASM

This implements some WASM bindings for the Rust [tls_parser](https://github.com/rusticata/tls-parser) crate.  It's used as the backend of a website that decodes TLS handshakes at https://williamlieurance.com/tls-handshake-parser

## Develop
```
wasm-pack build --dev
cd website
npm run start
```

## Build
```
wasm-pack build
cd website
npm run-script build
```
Everything you need will be in the `dist/` directory under `website/`.  Host those files and you're good to go.
