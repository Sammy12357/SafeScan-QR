// Camera QR decoding runs off the main thread. Only the capture button's
// caller may use a valid payload for analysis; locate messages are guidance.
// This is a classic worker so the pinned IIFE reader can load via importScripts.

"use strict";

const READER_ROOT = "/static/vendor/zxing-wasm/3.1.6/reader/";
const OPTIONS_URL = "/static/qr-decode-options.json?v=scanner-phase-2";
const MAX_INPUT_PIXELS = 16_000_000;
const MAX_CROP_PIXELS = 8_000_000;
const MAX_PAYLOAD_LENGTH = 4096;
const THRESHOLDS = [70, 115, 155];
const QUAD_POINTS = ["topLeft", "topRight", "bottomRight", "bottomLeft"];

let decoder = null;
let decodeOptions = null;
let startupError = null;
let running = false;
const pending = [];

const ready = (async () => {
  try {
    importScripts(READER_ROOT + "index.js");
    decoder = self.ZXingWASM;
    if (!decoder || typeof decoder.readBarcodes !== "function") throw new Error("decoder_missing");

    const response = await fetch(OPTIONS_URL, { cache: "force-cache" });
    if (!response.ok) throw new Error("options_unavailable");
    decodeOptions = await response.json();
    if (!decodeOptions.capture || !decodeOptions.locate) throw new Error("options_invalid");

    await decoder.prepareZXingModule({
      overrides: {
        locateFile: (name, prefix) => name.endsWith(".wasm") ? READER_ROOT + "zxing_reader.wasm" : prefix + name
      },
      fireImmediately: true
    });
    self.postMessage({ type: "ready" });
  } catch (_error) {
    startupError = "decoder_unavailable";
    self.postMessage({ type: "init-error", error: startupError });
  }
})();

function clockNow() {
  return self.performance && typeof self.performance.now === "function" ? self.performance.now() : Date.now();
}

function validDimensions(width, height, limit) {
  return Number.isSafeInteger(width) && Number.isSafeInteger(height) &&
    width > 0 && height > 0 && width * height <= limit;
}

function imageDataFromMessage(message) {
  if (message.bitmap) {
    const bitmap = message.bitmap;
    try {
      if (!validDimensions(bitmap.width, bitmap.height, MAX_INPUT_PIXELS)) throw new Error("image_too_large");
      if (typeof OffscreenCanvas !== "function") throw new Error("offscreen_canvas_unavailable");
      const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("canvas_unavailable");
      context.drawImage(bitmap, 0, 0);
      return context.getImageData(0, 0, bitmap.width, bitmap.height);
    } finally {
      if (typeof bitmap.close === "function") bitmap.close();
    }
  }

  const image = message.imageData;
  if (!image || !validDimensions(image.width, image.height, MAX_INPUT_PIXELS)) throw new Error("image_invalid");
  const pixels = image.data instanceof Uint8ClampedArray
    ? image.data
    : image.data instanceof ArrayBuffer ? new Uint8ClampedArray(image.data) : null;
  if (!pixels || pixels.length !== image.width * image.height * 4) throw new Error("image_invalid");
  // A transferred ImageData stays an ImageData in browsers. The explicit
  // constructor also accepts plain {data,width,height} from older clients.
  return image instanceof ImageData ? image : new ImageData(pixels, image.width, image.height);
}

function pointFromResult(point, transform) {
  if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) return null;
  return {
    x: transform.x + point.x / transform.scale,
    y: transform.y + point.y / transform.scale
  };
}

function quadFromResult(position, transform) {
  if (!position) return null;
  const quad = {};
  for (const corner of QUAD_POINTS) {
    quad[corner] = pointFromResult(position[corner], transform);
    if (!quad[corner]) return null;
  }
  return quad;
}

function normalizeSymbol(result, transform) {
  const text = typeof result.text === "string" ? result.text : "";
  const valid = result.isValid === true && text.trim().length > 0 && text.length <= MAX_PAYLOAD_LENGTH;
  return {
    text: valid ? text : "",
    valid,
    quad: quadFromResult(result.position, transform),
    format: typeof result.format === "string" ? result.format : "None",
    sequenceSize: Number.isInteger(result.sequenceSize) ? result.sequenceSize : -1,
    sequenceIndex: Number.isInteger(result.sequenceIndex) ? result.sequenceIndex : -1
  };
}

function boundingBox(quad, width, height) {
  if (!quad) return null;
  const points = QUAD_POINTS.map((corner) => quad[corner]);
  if (points.some((point) => !point || !Number.isFinite(point.x) || !Number.isFinite(point.y))) return null;
  const x0 = Math.max(0, Math.min(...points.map((point) => point.x)));
  const x1 = Math.min(width, Math.max(...points.map((point) => point.x)));
  const y0 = Math.max(0, Math.min(...points.map((point) => point.y)));
  const y1 = Math.min(height, Math.max(...points.map((point) => point.y)));
  if (x1 - x0 < 8 || y1 - y0 < 8) return null;
  return { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
}

function boxFromHint(hint, width, height) {
  if (!hint) return null;
  if (Array.isArray(hint)) {
    const points = hint.slice(0, 4).map((point) => ({ x: point.x, y: point.y }));
    if (points.length !== 4) return null;
    return boundingBox({ topLeft: points[0], topRight: points[1], bottomRight: points[2], bottomLeft: points[3] }, width, height);
  }
  if (Number.isFinite(hint.x) && Number.isFinite(hint.y) && Number.isFinite(hint.width) && Number.isFinite(hint.height)) {
    const x = Math.max(0, Math.min(width, hint.x));
    const y = Math.max(0, Math.min(height, hint.y));
    return { x, y, width: Math.max(0, Math.min(width - x, hint.width)), height: Math.max(0, Math.min(height - y, hint.height)) };
  }
  return boundingBox(hint, width, height);
}

function expandedRect(box, width, height) {
  const marginX = box.width * 0.25;
  const marginY = box.height * 0.25;
  const x0 = Math.max(0, Math.floor(box.x - marginX));
  const y0 = Math.max(0, Math.floor(box.y - marginY));
  const x1 = Math.min(width, Math.ceil(box.x + box.width + marginX));
  const y1 = Math.min(height, Math.ceil(box.y + box.height + marginY));
  return { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
}

function cropAndScale(source, rect, requestedScale, sourceCanvas) {
  const scale = Math.min(requestedScale, Math.sqrt(MAX_CROP_PIXELS / (rect.width * rect.height)));
  const outputWidth = Math.max(1, Math.round(rect.width * scale));
  const outputHeight = Math.max(1, Math.round(rect.height * scale));
  if (!validDimensions(outputWidth, outputHeight, MAX_CROP_PIXELS)) throw new Error("crop_too_large");

  if (sourceCanvas) {
    const canvas = new OffscreenCanvas(outputWidth, outputHeight);
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("canvas_unavailable");
    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = "high";
    context.drawImage(sourceCanvas, rect.x, rect.y, rect.width, rect.height, 0, 0, outputWidth, outputHeight);
    return { image: context.getImageData(0, 0, outputWidth, outputHeight), transform: { x: rect.x, y: rect.y, scale: outputWidth / rect.width } };
  }

  // Safari versions without OffscreenCanvas still decode off the main thread.
  // Nearest-neighbor upscaling is sufficient to widen tiny QR modules.
  const output = new Uint8ClampedArray(outputWidth * outputHeight * 4);
  if (outputWidth === rect.width * 2 && outputHeight === rect.height * 2 &&
      Number.isInteger(rect.x) && Number.isInteger(rect.y) && source.data.byteOffset % 4 === 0) {
    const from = new Uint32Array(source.data.buffer, source.data.byteOffset, source.width * source.height);
    const to = new Uint32Array(output.buffer);
    for (let y = 0; y < rect.height; y += 1) {
      const sourceRow = (rect.y + y) * source.width + rect.x;
      const targetRow = y * 2 * outputWidth;
      for (let x = 0; x < rect.width; x += 1) {
        const pixel = from[sourceRow + x];
        to[targetRow + x * 2] = pixel;
        to[targetRow + x * 2 + 1] = pixel;
      }
      to.copyWithin(targetRow + outputWidth, targetRow, targetRow + outputWidth);
    }
    return { image: new ImageData(output, outputWidth, outputHeight), transform: { x: rect.x, y: rect.y, scale: 2 } };
  }
  for (let y = 0; y < outputHeight; y += 1) {
    const sourceY = Math.min(source.height - 1, Math.floor(rect.y + y * rect.height / outputHeight));
    for (let x = 0; x < outputWidth; x += 1) {
      const sourceX = Math.min(source.width - 1, Math.floor(rect.x + x * rect.width / outputWidth));
      const sourceOffset = (sourceY * source.width + sourceX) * 4;
      const outputOffset = (y * outputWidth + x) * 4;
      output[outputOffset] = source.data[sourceOffset];
      output[outputOffset + 1] = source.data[sourceOffset + 1];
      output[outputOffset + 2] = source.data[sourceOffset + 2];
      output[outputOffset + 3] = source.data[sourceOffset + 3];
    }
  }
  return { image: new ImageData(output, outputWidth, outputHeight), transform: { x: rect.x, y: rect.y, scale: outputWidth / rect.width } };
}

function tileRects(width, height) {
  const tileWidth = Math.ceil(width * 0.6);
  const tileHeight = Math.ceil(height * 0.6);
  const right = width - tileWidth;
  const bottom = height - tileHeight;
  return [
    { x: 0, y: 0, width: tileWidth, height: tileHeight },
    { x: right, y: 0, width: tileWidth, height: tileHeight },
    { x: 0, y: bottom, width: tileWidth, height: tileHeight },
    { x: right, y: bottom, width: tileWidth, height: tileHeight },
    { x: Math.floor(right / 2), y: Math.floor(bottom / 2), width: tileWidth, height: tileHeight }
  ];
}

function thresholdImages(source) {
  const count = source.width * source.height;
  const gray = new Uint8Array(count);
  let minimum = 255;
  let maximum = 0;
  for (let pixel = 0, offset = 0; pixel < count; pixel += 1, offset += 4) {
    const value = Math.round(source.data[offset] * 0.299 + source.data[offset + 1] * 0.587 + source.data[offset + 2] * 0.114);
    gray[pixel] = value;
    minimum = Math.min(minimum, value);
    maximum = Math.max(maximum, value);
  }
  const span = Math.max(1, maximum - minimum);
  return THRESHOLDS.map((limit) => {
    const output = new Uint8ClampedArray(count * 4);
    for (let pixel = 0, offset = 0; pixel < count; pixel += 1, offset += 4) {
      const value = Math.round((gray[pixel] - minimum) * 255 / span) > limit ? 255 : 0;
      output[offset] = output[offset + 1] = output[offset + 2] = value;
      output[offset + 3] = 255;
    }
    return new ImageData(output, source.width, source.height);
  });
}

function symbolCenter(symbol) {
  if (!symbol.quad) return null;
  const points = QUAD_POINTS.map((corner) => symbol.quad[corner]);
  return { x: points.reduce((sum, point) => sum + point.x, 0) / 4, y: points.reduce((sum, point) => sum + point.y, 0) / 4 };
}

function samePhysicalCode(first, second) {
  if (first.text !== second.text || !first.quad || !second.quad) return false;
  const firstCenter = symbolCenter(first);
  const secondCenter = symbolCenter(second);
  const extent = (symbol) => {
    const xs = QUAD_POINTS.map((corner) => symbol.quad[corner].x);
    const ys = QUAD_POINTS.map((corner) => symbol.quad[corner].y);
    return Math.min(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys));
  };
  // Decoding a crop, a tile and the full frame produces slightly different
  // corners for one physical symbol. Separate same-text stickers have distant
  // centers and must remain separate for the ambiguity refusal.
  const tolerance = Math.max(12, Math.min(extent(first), extent(second)) * 0.25);
  return Math.hypot(firstCenter.x - secondCenter.x, firstCenter.y - secondCenter.y) < tolerance;
}

function collectSymbols(collection, results, transform) {
  for (const result of results || []) {
    const symbol = normalizeSymbol(result, transform);
    if (symbol.valid) {
      if (!collection.valid.has(symbol.text)) collection.valid.set(symbol.text, symbol);
      if (symbol.quad && !collection.validLocations.some((previous) => samePhysicalCode(previous, symbol))) {
        collection.validLocations.push(symbol);
      }
    } else if (symbol.quad) {
      const center = symbolCenter(symbol);
      if (!collection.invalid.some((previous) => {
        const prior = symbolCenter(previous);
        return prior && Math.hypot(prior.x - center.x, prior.y - center.y) < 24;
      })) collection.invalid.push(symbol);
    }
  }
}

function outputSymbols(collection) {
  const visible = [...collection.validLocations];
  for (const symbol of collection.valid.values()) {
    if (!visible.some((existing) => existing.text === symbol.text)) visible.push(symbol);
  }
  return [...visible, ...collection.invalid.slice(0, 4)];
}

function hasMultipleCodes(collection) {
  return collection.valid.size > 1 || collection.validLocations.length > 1;
}

function captureResult(collection, stage) {
  const symbols = outputSymbols(collection);
  return {
    symbols,
    stage,
    multipleCodes: hasMultipleCodes(collection),
    structuredAppend: symbols.some((symbol) => symbol.sequenceSize > 1)
  };
}

async function read(image, options) {
  return decoder.readBarcodes(image, options);
}

async function checkSecondWithMask(image, collection) {
  if (collection.valid.size !== 1 || hasMultipleCodes(collection)) return false;
  const first = collection.valid.values().next().value;
  const box = boundingBox(first.quad, image.width, image.height);
  if (!box) return false;
  const left = Math.max(0, Math.floor(box.x - 8));
  const top = Math.max(0, Math.floor(box.y - 8));
  const right = Math.min(image.width, Math.ceil(box.x + box.width + 8));
  const bottom = Math.min(image.height, Math.ceil(box.y + box.height + 8));
  const pixels = new Uint8ClampedArray(image.data);
  for (let y = top; y < bottom; y += 1) {
    pixels.fill(255, (y * image.width + left) * 4, (y * image.width + right) * 4);
  }
  const masked = new ImageData(pixels, image.width, image.height);
  collectSymbols(collection, await read(masked, decodeOptions.capture), { x: 0, y: 0, scale: 1 });
  return true;
}

async function decodeCapture(image, hint) {
  const collection = { valid: new Map(), validLocations: [], invalid: [] };
  const identity = { x: 0, y: 0, scale: 1 };
  let stage = "none";

  collectSymbols(collection, await read(image, decodeOptions.capture), identity);
  if (collection.valid.size) stage = "full";
  if (hasMultipleCodes(collection)) return captureResult(collection, stage);
  if (await checkSecondWithMask(image, collection)) return captureResult(collection, stage);

  let sourceCanvas = null;
  if (typeof OffscreenCanvas === "function") {
    const canvas = new OffscreenCanvas(image.width, image.height);
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (context) {
      context.putImageData(image, 0, 0);
      sourceCanvas = canvas;
    }
  }

  const boxes = [];
  const hinted = boxFromHint(hint, image.width, image.height);
  if (hinted && hinted.width >= 8 && hinted.height >= 8) boxes.push(hinted);
  if (collection.valid.size === 0) {
    const located = await read(image, decodeOptions.locate);
    collectSymbols(collection, located, identity);
    if (collection.valid.size) stage = "full";
    for (const result of located) {
      const box = boundingBox(quadFromResult(result.position, identity), image.width, image.height);
      if (box && !boxes.some((existing) => Math.hypot(existing.x - box.x, existing.y - box.y) < 24)) boxes.push(box);
    }
  }
  if (hasMultipleCodes(collection)) return captureResult(collection, stage);
  if (await checkSecondWithMask(image, collection)) return captureResult(collection, stage);

  for (const box of boxes.slice(0, 4)) {
    const rect = expandedRect(box, image.width, image.height);
    const scale = Math.max(1, Math.min(8, 600 / Math.min(box.width, box.height)));
    const crop = cropAndScale(image, rect, scale, sourceCanvas);
    collectSymbols(collection, await read(crop.image, decodeOptions.capture), crop.transform);
    if (collection.valid.size) stage = "roi";
    if (hasMultipleCodes(collection)) return captureResult(collection, stage);
  }
  if (await checkSecondWithMask(image, collection)) return captureResult(collection, stage);

  // Search every tile before returning a tile-found code. Returning after the
  // first successful tile could silently miss another QR elsewhere.
  for (const rect of tileRects(image.width, image.height)) {
    const crop = cropAndScale(image, rect, 2, sourceCanvas);
    collectSymbols(collection, await read(crop.image, decodeOptions.capture), crop.transform);
    if (collection.valid.size) stage = "tiles";
    if (hasMultipleCodes(collection)) return captureResult(collection, stage);
  }

  if (collection.valid.size === 0) {
    for (const thresholded of thresholdImages(image)) {
      collectSymbols(collection, await read(thresholded, decodeOptions.capture), identity);
      if (collection.valid.size) stage = "threshold";
      if (collection.valid.size === 1) await checkSecondWithMask(thresholded, collection);
      if (hasMultipleCodes(collection)) break;
    }
  }
  return captureResult(collection, stage);
}

async function decodeLocate(image) {
  // Locate mode keeps physical positions, even when two separate QRs contain
  // the same text. Guidance needs to show both outlines; capture's distinct
  // payload map is intentionally different.
  const results = await read(image, decodeOptions.locate);
  return {
    symbols: (results || []).map((result) => normalizeSymbol(result, { x: 0, y: 0, scale: 1 })).slice(0, 4),
    stage: "locate"
  };
}

async function processMessage(message) {
  const started = clockNow();
  let width = 0;
  let height = 0;
  try {
    await ready;
    if (startupError) throw new Error(startupError);
    const image = imageDataFromMessage(message);
    width = image.width;
    height = image.height;
    const result = message.mode === "locate" ? await decodeLocate(image) : await decodeCapture(image, message.roi);
    self.postMessage({ id: message.id, ...result, width, height, ms: Math.round(clockNow() - started) });
  } catch (error) {
    const code = error && /^(image_|crop_|canvas_|offscreen_|decoder_)/.test(error.message) ? error.message : "decode_failed";
    self.postMessage({ id: message.id, symbols: [], width, height, ms: Math.round(clockNow() - started), stage: "none", error: code });
  }
}

function runNext() {
  if (running || !pending.length) return;
  running = true;
  const message = pending.shift();
  processMessage(message).finally(() => {
    running = false;
    runNext();
  });
}

self.onmessage = (event) => {
  const message = event.data;
  if (!message || message.type !== "decode" || !Number.isSafeInteger(message.id)) return;
  if (message.mode !== "capture" && message.mode !== "locate") return;
  // Guidance frames are disposable. Never queue old locate work behind a
  // capture, which would delay the user's deliberate scan and grow memory.
  if (message.mode === "locate" && (running || pending.length)) {
    if (message.bitmap && typeof message.bitmap.close === "function") message.bitmap.close();
    self.postMessage({ id: message.id, symbols: [], stage: "skipped", ms: 0, error: "busy" });
    return;
  }
  pending.push(message);
  runNext();
};
