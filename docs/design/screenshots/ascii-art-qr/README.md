# ASCII art QR visual evidence

These panel screenshots were captured with headless Chromium against the local
FastAPI app at 375, 768, and 1440 px, in dark and light themes. The before
images use the existing Text QR output from `267a118` because ASCII art was not
yet an option. The after images use the new Cat or Flame ASCII art QR output.
All use plain mode and `https://example.com/art`, so the unchecked warning and
result label are visible.

The downloaded Cat and Flame PNG files are included here. ZXing decoded both
downloads and all 12 after screenshots back to `https://example.com/art`.
The browser reported no page errors. These checks cover the tested renders;
they do not substitute for testing every phone camera or print condition.
