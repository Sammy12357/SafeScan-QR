# Browser-rendered text QR frames

These four PNGs are screenshots of the white text QR preview at a 390 px mobile
viewport in Chromium, using the Sqafe monospace CSS. They use QR mask patterns
0–3 and all encode `https://sqafe.com/`. The label is outside the QR quiet zone.

Run `python scripts/qr_bench/bench_server.py --corpus tests/qr_corpus/text_qr`
to measure the server decoder against these displayed frames. The focused test
in `tests/test_qr_corpus_regression.py` requires all four to decode. These are
display fixtures; the renderer's source matrix and current browser layout are
also checked independently during feature testing.
