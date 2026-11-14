#!/usr/bin/env node
// Exercise the exact classic worker against the pinned corpus without a camera.
// Run `npm ci --prefix scripts/qr_bench` once, then this file from the repo root.
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import sharp from "sharp";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const corpus = path.join(root, "tests/qr_corpus/synthetic");
const reader = path.join(root, "static/vendor/zxing-wasm/3.1.6/reader");
const labels = JSON.parse(fs.readFileSync(path.join(corpus, "labels.json"), "utf8"));
const minimumCore = Number(process.argv[2] ?? 16);
if (!Number.isInteger(minimumCore) || minimumCore < 0 || minimumCore > 18) {
  throw new Error("Optional argument must be the minimum core successes (0–18)");
}

class ImageDataPolyfill {
  constructor(data, width, height) {
    this.data = data;
    this.width = width;
    this.height = height;
  }
}

let readyResolve;
let readyReject;
const ready = new Promise((resolve, reject) => {
  readyResolve = resolve;
  readyReject = reject;
});
const replies = new Map();
const worker = {
  ImageData: ImageDataPolyfill,
  Uint8ClampedArray,
  Uint8Array,
  ArrayBuffer,
  performance,
  postMessage(message) {
    if (message.type === "ready") readyResolve();
    else if (message.type === "init-error") readyReject(new Error(message.error));
    else replies.get(message.id)?.(message);
  },
  async fetch(url) {
    const filename = path.join(root, url.split("?")[0]);
    return { ok: true, json: async () => JSON.parse(fs.readFileSync(filename, "utf8")) };
  }
};
worker.self = worker;
vm.createContext(worker);
worker.importScripts = (url) => {
  vm.runInContext(fs.readFileSync(path.join(root, url), "utf8"), worker, { filename: url });
  // Node does not fetch a browser URL for wasm. Supply the same pinned binary
  // directly while still exercising the worker's initialization and options.
  const prepare = worker.ZXingWASM.prepareZXingModule;
  worker.ZXingWASM.prepareZXingModule = (arguments_) => prepare({
    ...arguments_,
    overrides: {
      ...arguments_.overrides,
      wasmBinary: fs.readFileSync(path.join(reader, "zxing_reader.wasm"))
    }
  });
};
vm.runInContext(fs.readFileSync(path.join(root, "static/qr-worker.js"), "utf8"), worker, { filename: "qr-worker.js" });
await Promise.race([
  ready,
  new Promise((_, reject) => setTimeout(() => reject(new Error("Worker did not become ready")), 5000))
]);

let nextId = 0;
async function imageData(bytes) {
  const { data, info } = await sharp(bytes).rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return new ImageDataPolyfill(new Uint8ClampedArray(data), info.width, info.height);
}

async function decode(image, mode = "capture") {
  const id = ++nextId;
  const response = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Worker timed out on message ${id}`)), 10_000);
    replies.set(id, (message) => {
      clearTimeout(timeout);
      replies.delete(id);
      resolve(message);
    });
  });
  worker.onmessage({ data: { type: "decode", id, mode, imageData: image } });
  return response;
}

function validTexts(message) {
  return [...new Set(message.symbols.filter((symbol) => symbol.valid).map((symbol) => symbol.text))];
}

let coreCorrect = 0;
let allCorrect = 0;
const timings = [];
for (const [filename, expected] of Object.entries(labels).sort(([a], [b]) => a.localeCompare(b))) {
  const response = await decode(await imageData(path.join(corpus, filename)));
  if (response.error) throw new Error(`${filename}: ${response.error}`);
  const actual = validTexts(response);
  const exact = actual.length === expected.length && expected.every((text) => actual.includes(text));
  if (exact) allCorrect += 1;
  if (Number(filename.slice(0, 2)) <= 18 && exact) coreCorrect += 1;
  if (expected.length > 1 && !response.multipleCodes) throw new Error(`${filename}: multi-code refusal was lost`);
  if (expected.length === 1 && response.multipleCodes) throw new Error(`${filename}: false multi-code report`);
  timings.push(response.ms);
  console.log(`${filename.padEnd(39)} ${exact ? "✓" : "×"} ${response.stage} ${response.ms}ms`);
}

// Two distinct physical QR codes with identical text must still be refused.
const clean = await sharp(path.join(corpus, "01_clean_centered.png"))
  .extract({ left: 480, top: 200, width: 320, height: 320 }).png().toBuffer();
const sameTextFrame = await sharp({ create: { width: 1280, height: 720, channels: 4, background: "#ffffff" } })
  .composite([{ input: clean, left: 220, top: 180 }, { input: clean, left: 740, top: 180 }])
  .png().toBuffer();
const duplicate = await decode(await imageData(sameTextFrame));
const physicalCodes = duplicate.symbols.filter((symbol) => symbol.valid && symbol.quad);
if (!duplicate.multipleCodes || physicalCodes.length < 2 || validTexts(duplicate).length !== 1) {
  throw new Error("Two same-text physical QRs were not marked as multiple codes");
}
const located = await decode(await imageData(sameTextFrame), "locate");
if (located.error || located.symbols.filter((symbol) => symbol.valid && symbol.quad).length < 2) {
  throw new Error("Locate mode dropped a separate same-text QR outline");
}
if (!Number.isFinite(located.stats?.sharpness)) throw new Error("Locate guidance lacks sharpness statistics");

// A clearly readable QR must not short-circuit the search for a tiny, distant
// second QR. The 58px symbol is recovered by the tile pass on the pinned WASM
// decoder, after the full-frame and masked reads find only the large symbol.
const secondPatch = await sharp(path.join(corpus, "22_two_codes.png"))
  .extract({ left: 720, top: 210, width: 275, height: 275 }).png().toBuffer();
const tinySecond = await sharp(secondPatch).resize(58, 58, { kernel: "nearest" }).png().toBuffer();
const mixedSizeFrame = await sharp({ create: { width: 1280, height: 720, channels: 4, background: "#ffffff" } })
  .composite([{ input: clean, left: 220, top: 180 }, { input: tinySecond, left: 1020, top: 65 }])
  .png().toBuffer();
const mixedSize = await decode(await imageData(mixedSizeFrame));
const expectedMixed = [labels["01_clean_centered.png"][0], labels["22_two_codes.png"][1]];
if (mixedSize.error || !mixedSize.multipleCodes ||
    !expectedMixed.every((value) => validTexts(mixedSize).includes(value))) {
  throw new Error("Tiny second QR escaped the full-frame multi-code refusal");
}

const cleanPatch = await sharp(path.join(corpus, "01_clean_centered.png"))
  .extract({ left: 480, top: 200, width: 320, height: 320 }).png().toBuffer();
const blurredPatch = await sharp(path.join(corpus, "11_motion_blur.png"))
  .extract({ left: 480, top: 200, width: 320, height: 320 }).png().toBuffer();
const cleanScore = await decode(await imageData(cleanPatch), "score");
const blurredScore = await decode(await imageData(blurredPatch), "score");
if (!(cleanScore.stats?.sharpness > blurredScore.stats?.sharpness)) {
  throw new Error("Worker sharpness score did not rank the clean QR above motion blur");
}

// A split QR can contain a URL-shaped first fragment. It must not be sent to
// risk analysis as though it were a complete destination.
for (const index of [1, 2, 3]) {
  const name = `structured-${String(index).padStart(2, "0")}.png`;
  const fragment = await decode(await imageData(path.join(root, "tests/qr_corpus/structured_append", name)));
  if (fragment.error || fragment.structuredAppend !== true ||
      !fragment.symbols.some((symbol) => symbol.sequenceSize === 3 && symbol.sequenceIndex === index - 1)) {
    throw new Error(`${name}: structured append metadata was lost`);
  }
}
if (!vm.runInContext(`captureResult({ validLocations: [], valid: new Map([["partial", {
  text: "partial", valid: true, quad: null, sequenceSize: 0, sequenceIndex: 0
}]]), invalid: [] }, "full").structuredAppend`, worker)) {
  throw new Error("Unknown-count structured append fragment was accepted");
}

timings.sort((a, b) => a - b);
const p95 = timings[Math.ceil(timings.length * 0.95) - 1];
console.log(`Worker exact: ${coreCorrect}/18 core; ${allCorrect}/24 all; p95 ${p95}ms`);
console.log("Same-text two-code refusal: pass");
console.log("Tiny second-code refusal: pass");
console.log("Separate locate outlines: pass");
console.log("Structured append fragments: refused");
console.log("Sharpness ranking: pass");
if (coreCorrect < minimumCore) process.exitCode = 1;
