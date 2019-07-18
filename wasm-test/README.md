## About

[**📚 Read this template tutorial! 📚**][template-docs]
This was built using a template using `cargo generate`.
[Learn more about `cargo generate` here.](https://github.com/ashleygwilliams/cargo-generate)

```
cargo generate --git https://github.com/rustwasm/wasm-pack-template.git --name my-project
cd my-project
```

## Requirements
[`wasm-pack`][https://rustwasm.github.io/wasm-pack/installer/]
[`npm`][https://www.npmjs.com/get-npm]

Modified [`rust-bitcoin][https://github.com/rust-bitcoin/rust-bitcoin.git] With secp256k1 version 0.14.


## Usage

1. Build: `wasm-pack build --dev`
2. `cd www`
3. `npm install`
4. `npm run start`
5. Browse to http://localhost:8080