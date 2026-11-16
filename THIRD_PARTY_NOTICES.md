# Third-party notices

Checked against `requirements.lock` and bundled browser/model assets on 2026-11-15. This inventory preserves license text with this source tree; it is not a conclusion that every distribution or trademark obligation is complete. See `docs/legal/attorney-packet.md` for decisions that need counsel or the owner.

## Browser, model, and font assets

| Asset | License and text | Notes |
| --- | --- | --- |
| three.js r164 (`static/vendor/three.module.js`) | MIT — [`static/vendor/THREE_LICENSE`](static/vendor/THREE_LICENSE) | Bundled on the same origin. |
| zxing-wasm 3.1.6 (`static/vendor/zxing-wasm/3.1.6/`) | MIT — [`LICENSE`](static/vendor/zxing-wasm/3.1.6/LICENSE); ZXing-C++ Apache-2.0 — [`ZXING_CPP_LICENSE`](static/vendor/zxing-wasm/3.1.6/ZXING_CPP_LICENSE) | Includes JavaScript and WebAssembly QR decoder. |
| WeChat QR models (`models/wechat_qr/`) | Apache-2.0 plus listed third-party terms — [`LICENSE`](models/wechat_qr/LICENSE) | Optional decoder, disabled by default. |
| Orbitron font (self-hosted in Phase 1) | SIL OFL-1.1 — [`third_party_licenses/Orbitron-OFL.txt`](third_party_licenses/Orbitron-OFL.txt) | Use the reserved font name according to the OFL; the font file is introduced by Phase 1. |

`static/safescan-logo.svg`, the SafeScan profile art, and the site-authored icon set are not open-source third-party grants. Ownership and name clearance remain open in the [brand inventory](docs/legal/brand-assets.md). The old Solana-marked hero image and device render were removed; product names remain plain text.

## Python runtime packages

This list is generated from the 97 packages pinned by `requirements.lock`. Each row links to retained license text from an exact-version package or the specified upstream release. The machine-readable review and primary package links are in [`docs/legal/runtime-dependency-licenses.json`](docs/legal/runtime-dependency-licenses.json). Most retained texts were extracted from an exact-version macOS environment; the `pypdfium2`, OpenCV, NumPy, SciPy, scikit-learn, Pillow, and h5py texts came from exact-version Linux x86-64 wheels. A row's main license may cover the Python wrapper but not every native component in its wheel; see the exceptions below.

| Package | Reviewed license | Retained license text |
| --- | --- | --- |
| absl-py 2.5.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/absl-py-2.5.1/licenses/LICENSE) |
| aiolimiter 1.3.0 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/aiolimiter-1.3.0/licenses/LICENSE.txt) |
| annotated-doc 0.0.6 | `MIT` | [`LICENSE`](third_party_licenses/runtime/annotated-doc-0.0.6/licenses/LICENSE) |
| annotated-types 0.8.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/annotated-types-0.8.0/licenses/LICENSE) |
| anyio 4.16.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/anyio-4.16.0/licenses/LICENSE) |
| arrow 1.4.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/arrow-1.4.0/licenses/LICENSE) |
| astunparse 1.6.3 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/astunparse-1.6.3/LICENSE) |
| base58 2.1.1 | `MIT` | [`COPYING`](third_party_licenses/runtime/base58-2.1.1/COPYING) |
| boto3 1.35.99 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/boto3-1.35.99/LICENSE); [`NOTICE`](third_party_licenses/runtime/boto3-1.35.99/NOTICE) |
| botocore 1.35.99 | `Apache-2.0` | [`LICENSE.txt`](third_party_licenses/runtime/botocore-1.35.99/LICENSE.txt); [`NOTICE`](third_party_licenses/runtime/botocore-1.35.99/NOTICE) |
| certifi 2026.10.23 | `MPL-2.0` | [`LICENSE`](third_party_licenses/runtime/certifi-2026.10.23/licenses/LICENSE) |
| cffi 2.1.1 | `MIT-0` | [`LICENSE`](third_party_licenses/runtime/cffi-2.1.1/licenses/LICENSE) |
| charset-normalizer 3.5.2 | `MIT` | [`LICENSE`](third_party_licenses/runtime/charset-normalizer-3.5.2/licenses/LICENSE) |
| click 8.5.1 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/click-8.5.1/licenses/LICENSE.txt) |
| cloudpickle 3.1.2 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/cloudpickle-3.1.2/licenses/LICENSE) |
| construct 2.10.70 | `MIT` | [`LICENSE`](third_party_licenses/runtime/construct-2.10.70/LICENSE) |
| construct-typing 0.8.1 | `MIT` | [`LICENSE`](third_party_licenses/runtime/construct-typing-0.8.1/licenses/LICENSE) |
| cryptography 50.0.2 | `Apache-2.0 OR BSD-3-Clause` | [`licenses/LICENSE`](third_party_licenses/runtime/cryptography-50.0.2/licenses/LICENSE); [`licenses/LICENSE.APACHE`](third_party_licenses/runtime/cryptography-50.0.2/licenses/LICENSE.APACHE); [`licenses/LICENSE.BSD`](third_party_licenses/runtime/cryptography-50.0.2/licenses/LICENSE.BSD) |
| fastapi 0.162.7 | `MIT` | [`LICENSE`](third_party_licenses/runtime/fastapi-0.162.7/licenses/LICENSE) |
| filelock 4.2.10 | `MIT` | [`LICENSE`](third_party_licenses/runtime/filelock-4.2.10/licenses/LICENSE) |
| flatbuffers 25.12.19 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/flatbuffers-25.12.19/LICENSE) |
| gast 0.7.0 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/gast-0.7.0/licenses/LICENSE) |
| google-auth 2.49.2 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/google-auth-2.49.2/licenses/LICENSE) |
| google-pasta 0.2.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/google-pasta-0.2.0/LICENSE) |
| grpcio 1.85.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/grpcio-1.85.1/licenses/LICENSE) |
| h11 0.16.0 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/h11-0.16.0/licenses/LICENSE.txt) |
| h2 4.4.1 | `MIT` | [`LICENSE`](third_party_licenses/runtime/h2-4.4.1/licenses/LICENSE) |
| h5py 3.16.0 | `BSD-3-Clause` | [`licenses/LICENSE`](third_party_licenses/runtime/h5py-3.16.0/licenses/LICENSE); [`licenses/licenses/license.txt`](third_party_licenses/runtime/h5py-3.16.0/licenses/licenses/license.txt); [`licenses/lzf/LICENSE.txt`](third_party_licenses/runtime/h5py-3.16.0/licenses/lzf/LICENSE.txt) |
| hpack 4.2.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/hpack-4.2.0/licenses/LICENSE) |
| httpcore2 2.16.0 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/httpcore2-2.16.0/licenses/LICENSE.md) |
| httptools 0.6.4 | `MIT` | [`LICENSE`](third_party_licenses/runtime/httptools-0.6.4/LICENSE) |
| httpx2 2.16.0 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/httpx2-2.16.0/licenses/LICENSE.md) |
| hyperframe 6.1.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/hyperframe-6.1.0/LICENSE) |
| idna 3.20 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/idna-3.20/licenses/LICENSE.md) |
| jinja2 3.1.6 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/jinja2-3.1.6/licenses/LICENSE.txt) |
| jmespath 1.1.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/jmespath-1.1.0/LICENSE) |
| joblib 1.6.0 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/joblib-1.6.0/licenses/LICENSE.txt) |
| jsonalias 0.1.1 | `MIT` | [`LICENSE`](third_party_licenses/runtime/jsonalias-0.1.1/LICENSE) |
| keras 3.15.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/keras-3.15.1/licenses/LICENSE) |
| libclang 18.1.1 | `Apache-2.0` | [`LICENSE.TXT`](third_party_licenses/runtime/libclang-18.1.1/LICENSE.TXT) |
| markdown 3.11.3 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/markdown-3.11.3/licenses/LICENSE.md) |
| markdown-it-py 4.3.0 | `MIT` | [`licenses/LICENSE`](third_party_licenses/runtime/markdown-it-py-4.3.0/licenses/LICENSE); [`licenses/LICENSE.markdown-it`](third_party_licenses/runtime/markdown-it-py-4.3.0/licenses/LICENSE.markdown-it) |
| markupsafe 3.0.4 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/markupsafe-3.0.4/licenses/LICENSE.txt) |
| mdurl 0.1.2 | `MIT` | [`LICENSE`](third_party_licenses/runtime/mdurl-0.1.2/LICENSE) |
| ml-dtypes 0.6.0 | `Apache-2.0` | [`licenses/LICENSE`](third_party_licenses/runtime/ml-dtypes-0.6.0/licenses/LICENSE); [`licenses/LICENSE.eigen`](third_party_licenses/runtime/ml-dtypes-0.6.0/licenses/LICENSE.eigen) |
| namex 0.1.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/namex-0.1.0/licenses/LICENSE) |
| numpy 2.4.6 | `BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0` | [`licenses/LICENSE.txt`](third_party_licenses/runtime/numpy-2.4.6/licenses/LICENSE.txt); [`licenses/numpy/_core/include/numpy/libdivide/LICENSE.txt`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/include/numpy/libdivide/LICENSE.txt); [`licenses/numpy/_core/src/common/pythoncapi-compat/COPYING`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/src/common/pythoncapi-compat/COPYING); [`licenses/numpy/_core/src/highway/LICENSE`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/src/highway/LICENSE); [`licenses/numpy/_core/src/multiarray/dragon4_LICENSE.txt`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/src/multiarray/dragon4_LICENSE.txt); [`licenses/numpy/_core/src/npysort/x86-simd-sort/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/src/npysort/x86-simd-sort/LICENSE.md); [`licenses/numpy/_core/src/umath/svml/LICENSE`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/_core/src/umath/svml/LICENSE); [`licenses/numpy/fft/pocketfft/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/fft/pocketfft/LICENSE.md); [`licenses/numpy/linalg/lapack_lite/LICENSE.txt`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/linalg/lapack_lite/LICENSE.txt); [`licenses/numpy/ma/LICENSE`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/ma/LICENSE); [`licenses/numpy/random/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/LICENSE.md); [`licenses/numpy/random/src/distributions/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/distributions/LICENSE.md); [`licenses/numpy/random/src/mt19937/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/mt19937/LICENSE.md); [`licenses/numpy/random/src/pcg64/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/pcg64/LICENSE.md); [`licenses/numpy/random/src/philox/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/philox/LICENSE.md); [`licenses/numpy/random/src/sfc64/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/sfc64/LICENSE.md); [`licenses/numpy/random/src/splitmix64/LICENSE.md`](third_party_licenses/runtime/numpy-2.4.6/licenses/numpy/random/src/splitmix64/LICENSE.md) |
| opencv-contrib-python-headless 4.14.0.94 | `MIT AND Apache-2.0` | [`LICENSE-3RD-PARTY.txt`](third_party_licenses/runtime/opencv-contrib-python-headless-4.14.0.94/LICENSE-3RD-PARTY.txt); [`LICENSE.txt`](third_party_licenses/runtime/opencv-contrib-python-headless-4.14.0.94/LICENSE.txt) |
| opentelemetry-api 1.45.2 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/opentelemetry-api-1.45.2/licenses/LICENSE) |
| opt-einsum 3.4.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/opt-einsum-3.4.0/licenses/LICENSE) |
| optree 0.20.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/optree-0.20.0/licenses/LICENSE) |
| packaging 26.3 | `Apache-2.0 OR BSD-3-Clause` | [`licenses/LICENSE`](third_party_licenses/runtime/packaging-26.3/licenses/LICENSE); [`licenses/LICENSE.APACHE`](third_party_licenses/runtime/packaging-26.3/licenses/LICENSE.APACHE); [`licenses/LICENSE.BSD`](third_party_licenses/runtime/packaging-26.3/licenses/LICENSE.BSD) |
| pillow 13.0.0 | `MIT-CMU` | [`LICENSE`](third_party_licenses/runtime/pillow-13.0.0/licenses/LICENSE) |
| prometheus-client 0.21.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/prometheus-client-0.21.1/LICENSE); [`NOTICE`](third_party_licenses/runtime/prometheus-client-0.21.1/NOTICE) |
| protobuf 7.36.2 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/protobuf-7.36.2/LICENSE) |
| pyasn1 0.6.5 | `BSD-2-Clause` | [`LICENSE.rst`](third_party_licenses/runtime/pyasn1-0.6.5/licenses/LICENSE.rst) |
| pyasn1-modules 0.4.2 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/pyasn1-modules-0.4.2/licenses/LICENSE.txt) |
| pycparser 3.12 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/pycparser-3.12/licenses/LICENSE) |
| pydantic 2.14.3 | `MIT` | [`LICENSE`](third_party_licenses/runtime/pydantic-2.14.3/licenses/LICENSE) |
| pydantic-core 2.50.4 | `MIT` | [`LICENSE`](third_party_licenses/runtime/pydantic-core-2.50.4/licenses/LICENSE) |
| pygments 2.21.0 | `BSD-2-Clause` | [`LICENSE`](third_party_licenses/runtime/pygments-2.21.0/licenses/LICENSE) |
| pypdfium2 5.15.2 | `Apache-2.0 OR BSD-3-Clause` | [`Apache-2.0.txt`](third_party_licenses/pypdfium2-5.15.2-linux-x86_64/LICENSES/Apache-2.0.txt); [`BSD-3-Clause.txt`](third_party_licenses/pypdfium2-5.15.2-linux-x86_64/LICENSES/BSD-3-Clause.txt); [`pdfium-binaries.txt`](third_party_licenses/pypdfium2-5.15.2-linux-x86_64/BUILD_LICENSES/pdfium-binaries.txt); [all 37 wheel notice files](third_party_licenses/pypdfium2-5.15.2-linux-x86_64/) |
| python-dateutil 2.9.0.post0 | `BSD-3-Clause OR Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/python-dateutil-2.9.0.post0/LICENSE) |
| python-dotenv 1.2.4 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/python-dotenv-1.2.4/licenses/LICENSE) |
| python-multipart 0.0.33 | `Apache-2.0` | [`LICENSE.txt`](third_party_licenses/runtime/python-multipart-0.0.33/licenses/LICENSE.txt) |
| python-whois 0.9.6 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/python-whois-0.9.6/licenses/LICENSE.txt) |
| pyzbar 0.1.9 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/pyzbar-0.1.9/LICENSE.txt) |
| qrcode 8.2 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/qrcode-8.2/LICENSE) |
| requests 2.34.2 | `Apache-2.0` | [`licenses/LICENSE`](third_party_licenses/runtime/requests-2.34.2/licenses/LICENSE); [`licenses/NOTICE`](third_party_licenses/runtime/requests-2.34.2/licenses/NOTICE) |
| requests-file 3.0.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/requests-file-3.0.1/licenses/LICENSE) |
| rich 15.0.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/rich-15.0.0/licenses/LICENSE) |
| s3transfer 0.10.4 | `Apache-2.0` | [`LICENSE.txt`](third_party_licenses/runtime/s3transfer-0.10.4/LICENSE.txt) |
| scikit-learn 1.6.1 | `BSD-3-Clause` | [`COPYING`](third_party_licenses/runtime/scikit-learn-1.6.1/COPYING) |
| scipy 1.17.1 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/scipy-1.17.1/LICENSE.txt) |
| setuptools 84.2.1 | `MIT` | [`LICENSE`](third_party_licenses/runtime/setuptools-84.2.1/licenses/LICENSE) |
| six 1.17.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/six-1.17.0/LICENSE) |
| solana 0.42.0 | `MIT` | [`LICENSE`](third_party_licenses/runtime/solana-0.42.0/licenses/LICENSE) |
| solders 0.29.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/solders-0.29.0/licenses/LICENSE) |
| starlette 1.10.0 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/starlette-1.10.0/licenses/LICENSE.md) |
| tensorboard 2.20.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/tensorboard-2.20.0/licenses/LICENSE) |
| tensorboard-data-server 0.7.2 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/tensorboard-data-server-0.7.2/LICENSE) |
| tensorflow 2.20.0 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/tensorflow-2.20.0/LICENSE) |
| termcolor 3.3.0 | `MIT` | [`COPYING.txt`](third_party_licenses/runtime/termcolor-3.3.0/licenses/COPYING.txt) |
| threadpoolctl 3.8.0 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/threadpoolctl-3.8.0/licenses/LICENSE) |
| tldextract 5.4.0 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/tldextract-5.4.0/licenses/LICENSE) |
| truststore 0.10.5 | `MIT` | [`LICENSE`](third_party_licenses/runtime/truststore-0.10.5/licenses/LICENSE) |
| typing-extensions 4.16.0 | `PSF-2.0` | [`LICENSE`](third_party_licenses/runtime/typing-extensions-4.16.0/licenses/LICENSE) |
| typing-inspection 0.4.5 | `MIT` | [`LICENSE`](third_party_licenses/runtime/typing-inspection-0.4.5/licenses/LICENSE) |
| tzdata 2026.6 | `Apache-2.0` | [`licenses/LICENSE`](third_party_licenses/runtime/tzdata-2026.6/licenses/LICENSE); [`licenses/licenses/LICENSE_APACHE`](third_party_licenses/runtime/tzdata-2026.6/licenses/licenses/LICENSE_APACHE) |
| urllib3 2.8.0 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/urllib3-2.8.0/licenses/LICENSE.txt) |
| uvicorn 0.39.0 | `BSD-3-Clause` | [`LICENSE.md`](third_party_licenses/runtime/uvicorn-0.39.0/licenses/LICENSE.md) |
| uvloop 0.21.0 | `MIT` | [`LICENSE-APACHE`](third_party_licenses/runtime/uvloop-0.21.0/LICENSE-APACHE); [`LICENSE-MIT`](third_party_licenses/runtime/uvloop-0.21.0/LICENSE-MIT) |
| websockets 17.4 | `BSD-3-Clause` | [`LICENSE`](third_party_licenses/runtime/websockets-17.4/licenses/LICENSE) |
| werkzeug 3.1.9 | `BSD-3-Clause` | [`LICENSE.txt`](third_party_licenses/runtime/werkzeug-3.1.9/licenses/LICENSE.txt) |
| wheel 0.48.0 | `MIT` | [`LICENSE.txt`](third_party_licenses/runtime/wheel-0.48.0/licenses/LICENSE.txt) |
| wrapt 2.5.2 | `BSD-2-Clause` | [`LICENSE`](third_party_licenses/runtime/wrapt-2.5.2/licenses/LICENSE) |
| zxing-cpp 3.1.1 | `Apache-2.0` | [`LICENSE`](third_party_licenses/runtime/zxing-cpp-3.1.1/licenses/LICENSE) |

## Native wheel and source exceptions

- `pypdfium2==5.15.2`: the retained `BUILD_LICENSES` and `LICENSES` files came from the exact Linux x86-64 `manylinux_2_17` wheel, SHA-256 `dc31aea5b0fb9fefc9b537a65f4113980b2c40798445736a7e6565bc85161e37`. The wheel contains notices for several build variants; the presence of a text file does not establish that component is linked into this variant. Check the deployed architecture if it changes.
- `opencv-contrib-python-headless==4.14.0.94`: Python packaging is MIT, OpenCV is Apache-2.0, and [the project states every wheel includes FFmpeg under LGPL-2.1](https://pypi.org/project/opencv-contrib-python-headless/4.14.0.94/). Its retained `LICENSE-3RD-PARTY.txt` is part of the notice set. Counsel should confirm LGPL distribution and dynamic-linking obligations for the deployed image.
- `numpy` and `scipy` Linux wheel license files list GCC runtime libraries under GPL-3.0-or-later with the GCC Runtime Library Exception. The exception may permit use with non-GPL programs, but its applicability to the deployed wheel needs counsel review. `scikit-learn`, `h5py`, and `tensorflow` are also compiled wheels and may include native or generated notices beyond their top-level license. The retained wheel notices are evidence, not a full binary composition audit. TensorFlow 2.20.0 uses the [upstream release license](https://github.com/tensorflow/tensorflow/blob/v2.20.0/LICENSE), because its wheel is too large to copy solely for this inventory.
- `flatbuffers==25.12.19`, `jsonalias==0.1.1`, and `tensorboard-data-server==0.7.2` wheels lacked a license text file. Their rows retain their respective upstream project license, with TensorBoard’s parent project Apache text used for `tensorboard-data-server`. Confirm the latter binary’s Rust component notices before distributing it outside the server.
- For packages whose retained notices came from the macOS environment, obtain and compare the actual Linux wheel notices before distributing a deployable server image. The CI gate checks the reviewed top-level package license and version, not every platform-specific native library or its notice.
- Development-only packages are not covered by the runtime CI gate. If SafeScan ships source or a client package, prepare a distribution-specific notice bundle.

## SafeScan code license

The repository has no root `LICENSE`. The business owner and an IP attorney must choose and approve SafeScan’s own code terms and verify ownership. This file grants no rights in SafeScan code and does not substitute for a root license.
