# Bundled font assets

This is an engineering inventory of redistributed font files. The license
texts ship beside the corresponding font files in `static/fonts/`.

| Asset | Source and pinned revision | License and notice | Use |
| --- | --- | --- | --- |
| `static/fonts/Orbitron-wght.ttf` | [Google Fonts Orbitron](https://github.com/google/fonts/tree/main/ofl/orbitron) | SIL Open Font License 1.1; `static/fonts/Orbitron-OFL.txt` | Site typography |
| `static/fonts/IBMPlexMono-Bold.ttf` | [Google Fonts IBM Plex Mono at `7af0d90`](https://github.com/google/fonts/tree/7af0d90b4d532ffa4b041937b560c6df4e7b1e95/ofl/ibmplexmono) | Copyright © 2017 IBM Corp.; SIL Open Font License 1.1, Reserved Font Name “Plex”; `static/fonts/IBMPlexMono-OFL.txt` | Server-rendered ASCII art QR PNG |

The IBM Plex Mono file has SHA-256
`ac27abd6450a64dd94467580a02fe6235156d5b92f2926ebbc8e7489df64e0be`.
The QR renderer loads this bundled path so its output does not depend on fonts
installed on the host.
