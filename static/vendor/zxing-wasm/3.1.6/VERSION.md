# Vendored zxing-wasm reader

- Package: [`zxing-wasm@3.1.6`](https://www.npmjs.com/package/zxing-wasm/v/3.1.6)
- Source tarball: `https://registry.npmjs.org/zxing-wasm/-/zxing-wasm-3.1.6.tgz`
- ZXing-C++ commit reported by the IIFE build: `2c3dcfeffa7878950a58c1703c86774a428b0c91`
- Intended use: same pinned reader for the Phase 0 benchmark and later self-hosted web worker. The site does not load it in Phase 0.

| File | SHA-256 |
| --- | --- |
| `reader/index.js` | `ffd72d59d54082194f7c086b384dcd930bdeb0c5b39fbb13779694e69bb0d344` |
| `reader/zxing_reader.wasm` | `5003fb4b88c4fbd1fd518a2fd8c8ad365c519e183a08c03a322dddfea3cea84e` |

The `zxing-wasm` wrapper is MIT licensed; see [LICENSE](LICENSE). Its ZXing-C++ component is Apache-2.0 licensed; see [ZXING_CPP_LICENSE](ZXING_CPP_LICENSE). The TypeScript declaration excerpts in `types/` come from the same package tarball and document the exact result and option fields used by the worker.
