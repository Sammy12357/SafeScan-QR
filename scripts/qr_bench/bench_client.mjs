#!/usr/bin/env node
// Compare the current 720px jsQR capture path with the pinned, locally vendored
// zxing-wasm reader. This is a benchmark tool; the website does not import it.
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import jsQR from "jsqr";
import sharp from "sharp";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "../..");
const vendorDir = path.join(root, "static/vendor/zxing-wasm/3.1.6/reader");
const options = JSON.parse(fs.readFileSync(path.join(root, "static/qr-decode-options.json"), "utf8"));
const thresholds = [55, 70, 85, 95, 115, 135, 155, 185];

function args() {
  const result = { corpus: "synthetic", limit: 0, min: null };
  for (let i = 2; i < process.argv.length; i += 1) {
    const flag = process.argv[i];
    if (flag === "--corpus") result.corpus = process.argv[++i];
    else if (flag === "--limit") result.limit = Number(process.argv[++i]);
    else if (flag === "--min") result.min = Number(process.argv[++i]);
    else throw new Error(`Unknown argument: ${flag}`);
  }
  if (!["synthetic", "boofcv"].includes(result.corpus)) throw new Error("--corpus must be synthetic or boofcv");
  return result;
}

function corpusFiles(corpus) {
  if (corpus === "synthetic") {
    const base = path.join(root, "tests/qr_corpus/synthetic");
    const labels = JSON.parse(fs.readFileSync(path.join(base, "labels.json"), "utf8"));
    return Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)).map(([name, expected]) => ({
      name, file: path.join(base, name), category: path.parse(name).name.replace(/[-_]\d+$/, ""), expected,
    }));
  }
  const base = path.join(root, ".cache/qr_corpus/boofcv");
  if (!fs.existsSync(base)) throw new Error("BoofCV corpus missing; run python scripts/qr_bench/fetch_boofcv.py");
  const found = [];
  const walk = (folder) => {
    for (const item of fs.readdirSync(folder, { withFileTypes: true })) {
      const full = path.join(folder, item.name);
      if (item.isDirectory()) walk(full);
      else if (/\.(png|jpe?g|webp)$/i.test(item.name)) {
        const rel = path.relative(base, full);
        const parts = rel.split(path.sep);
        const category = parts[0] === "qrcodes" && parts[1] === "detection"
          ? (parts[2] || "uncategorized")
          : (parts[0] === "qrcodes" && parts[1] === "decoding" ? "decoding"
            : (parts.length > 1 ? parts[0] : "uncategorized"));
        found.push({ name: rel, file: full, category, expected: null });
      }
    }
  };
  walk(base);
  return found.sort((a, b) => a.name.localeCompare(b.name));
}

class ImageDataPolyfill {
  constructor(data, width, height) { this.data = data; this.width = width; this.height = height; }
}
globalThis.ImageData = ImageDataPolyfill;
vm.runInThisContext(fs.readFileSync(path.join(vendorDir, "index.js"), "utf8"), { filename: "zxing-wasm-vendored.js" });
const zxing = globalThis.ZXingWASM;
if (typeof zxing?.readBarcodes !== "function") throw new Error("Vendored ZXingWASM reader failed to load");
await zxing.prepareZXingModule({
  overrides: { wasmBinary: fs.readFileSync(path.join(vendorDir, "zxing_reader.wasm")) },
  fireImmediately: true,
});

function unique(values) { return [...new Set(values.filter((v) => typeof v === "string" && v.length))]; }

function jsQrOneOrTwo(pixels, width, height) {
  const first = jsQR(pixels, width, height, { inversionAttempts: "attemptBoth" });
  if (!first?.data) return [];
  const values = [first.data];
  const corners = first.location && [
    first.location.topLeftCorner, first.location.topRightCorner,
    first.location.bottomLeftCorner, first.location.bottomRightCorner,
  ];
  if (corners?.every((point) => Number.isFinite(point?.x) && Number.isFinite(point?.y))) {
    const masked = new Uint8ClampedArray(pixels);
    const x0 = Math.max(0, Math.floor(Math.min(...corners.map((p) => p.x)) - 8));
    const x1 = Math.min(width, Math.ceil(Math.max(...corners.map((p) => p.x)) + 8));
    const y0 = Math.max(0, Math.floor(Math.min(...corners.map((p) => p.y)) - 8));
    const y1 = Math.min(height, Math.ceil(Math.max(...corners.map((p) => p.y)) + 8));
    for (let y = y0; y < y1; y += 1) {
      for (let x = x0; x < x1; x += 1) {
        const offset = (y * width + x) * 4;
        masked.fill(255, offset, offset + 4);
      }
    }
    const second = jsQR(masked, width, height, { inversionAttempts: "attemptBoth" });
    if (second?.data && second.data !== first.data) values.push(second.data);
  }
  return values;
}

function jsQrCapture(pixels, width, height) {
  const raw = jsQrOneOrTwo(pixels, width, height);
  if (raw.length) return raw;
  const count = width * height;
  const gray = new Uint8ClampedArray(count);
  let low = 255, high = 0;
  for (let pixel = 0, offset = 0; pixel < count; pixel += 1, offset += 4) {
    const value = Math.round(pixels[offset] * 0.299 + pixels[offset + 1] * 0.587 + pixels[offset + 2] * 0.114);
    gray[pixel] = value;
    low = Math.min(low, value);
    high = Math.max(high, value);
  }
  const span = Math.max(1, high - low);
  const enhanced = new Uint8ClampedArray(pixels.length);
  for (const threshold of thresholds) {
    for (let pixel = 0, offset = 0; pixel < count; pixel += 1, offset += 4) {
      const value = Math.round((gray[pixel] - low) * 255 / span) > threshold ? 255 : 0;
      enhanced[offset] = enhanced[offset + 1] = enhanced[offset + 2] = value;
      enhanced[offset + 3] = 255;
    }
    const result = jsQrOneOrTwo(enhanced, width, height);
    if (result.length) return result;
  }
  return [];
}

function isSuccess(actual, expected) {
  if (!expected) return actual.length > 0;
  return expected.length === actual.length && expected.every((value) => actual.includes(value));
}

function summary(rows) {
  const times = rows.map((row) => row.ms).sort((a, b) => a - b);
  const percentile = (p) => times.length ? times[Math.min(times.length - 1, Math.ceil(p * times.length) - 1)] : 0;
  return { read: rows.filter((row) => row.ok).length, total: rows.length,
    rate: rows.length ? rows.filter((row) => row.ok).length / rows.length : 0,
    p50_ms: percentile(0.5), p95_ms: percentile(0.95), max_ms: times.at(-1) ?? 0 };
}

async function rawImage(file, maxSide = null) {
  let pipeline = sharp(file).rotate();
  if (maxSide) pipeline = pipeline.resize({ width: maxSide, height: maxSide, fit: "inside", withoutEnlargement: true });
  const { data, info } = await pipeline.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return new ImageDataPolyfill(new Uint8ClampedArray(data), info.width, info.height);
}

const cli = args();
const files = corpusFiles(cli.corpus).slice(0, cli.limit || undefined);
if (!files.length) throw new Error("Corpus has no images");
const rows = [];
for (const item of files) {
  const native = await rawImage(item.file);
  const scaled = await rawImage(item.file, 720);
  const engines = {};
  for (const [name, decode] of Object.entries({
    jsqr_720: () => jsQrCapture(scaled.data, scaled.width, scaled.height),
    wasm_locate: async () => unique((await zxing.readBarcodes(native, options.locate)).filter((r) => r.isValid).map((r) => r.text)),
    wasm_capture: async () => unique((await zxing.readBarcodes(native, options.capture)).filter((r) => r.isValid).map((r) => r.text)),
  })) {
    const start = performance.now();
    const actual = await decode();
    engines[name] = { ok: isSuccess(actual, item.expected), count: actual.length, ms: Math.round((performance.now() - start) * 10) / 10 };
  }
  rows.push({ name: item.name, category: item.category, engines });
  if (cli.corpus === "synthetic") {
    console.log(`${item.name.padEnd(42)} jsQR ${engines.jsqr_720.ok ? "✓" : "×"}  locate ${engines.wasm_locate.ok ? "✓" : "×"}  capture ${engines.wasm_capture.ok ? "✓" : "×"}`);
  }
}

const categories = {};
for (const category of [...new Set(rows.map((row) => row.category))].sort()) {
  categories[category] = {};
  for (const engine of ["jsqr_720", "wasm_locate", "wasm_capture"]) {
    categories[category][engine] = summary(rows.filter((row) => row.category === category).map((row) => row.engines[engine]));
  }
}
const totals = {};
for (const engine of ["jsqr_720", "wasm_locate", "wasm_capture"]) totals[engine] = summary(rows.map((row) => row.engines[engine]));
const gitSha = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const report = { corpus: cli.corpus, git_sha: gitSha, node: process.version, zxing_wasm: zxing.ZXING_WASM_VERSION,
  options, totals, categories, cases: rows };
const output = path.join(root, `.cache/qr_bench/client-${cli.corpus}-${gitSha}.json`);
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
console.log("Category                         jsQR@720  wasm locate  wasm capture");
for (const [category, values] of Object.entries(categories)) {
  const cell = (engine) => `${values[engine].read}/${values[engine].total}`;
  console.log(`${category.padEnd(32)} ${cell("jsqr_720").padStart(7)}  ${cell("wasm_locate").padStart(11)}  ${cell("wasm_capture").padStart(12)}`);
}
for (const [engine, value] of Object.entries(totals)) console.log(`${engine}: ${value.read}/${value.total}, p50 ${value.p50_ms} ms, p95 ${value.p95_ms} ms, max ${value.max_ms} ms`);
console.log(`Report: ${output}`);
if (cli.min !== null && totals.wasm_capture.read < cli.min) process.exitCode = 1;
