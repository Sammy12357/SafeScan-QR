#!/usr/bin/env node
// Camera lifecycle regression using browser-shaped fakes; no physical device.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const code = fs.readFileSync(path.join(root, "static/qr-camera.js"), "utf8");

class Emitter {
  constructor() { this.listeners = new Map(); }
  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(handler);
  }
  removeEventListener(type, handler) { this.listeners.get(type)?.delete(handler); }
  async dispatch(type, event = {}) {
    for (const handler of [...(this.listeners.get(type) || [])]) await handler(event);
  }
}

class FakeElement extends Emitter {
  constructor() {
    super();
    this.hidden = false;
    this.disabled = false;
    this.dataset = {};
    this.attributes = {};
    this.textContent = "";
    this.classes = new Set();
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
      toggle: (name, yes) => yes ? this.classes.add(name) : this.classes.delete(name),
    };
  }
  setAttribute(name, value) { this.attributes[name] = value; }
  getContext() { return {
    setTransform() {}, clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, closePath() {}, stroke() {},
    drawImage() {}, putImageData() {},
    getImageData: (_x, _y, width, height) => ({ width, height, data: new Uint8ClampedArray(width * height * 4) }),
  }; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 640, height: 480 }; }
  remove() { document.currentModal = null; }
}

const elements = Object.fromEntries([
  "video", ".qr-camera-status", ".qr-camera-close", ".qr-camera-capture",
  ".qr-camera-controls", ".qr-camera-switch", ".qr-camera-zoom",
  ".qr-camera-torch", ".qr-camera-retry",
  ".qr-camera-auto", ".qr-camera-server-offer", ".qr-camera-server-send",
  ".qr-camera-overlay", ".qr-camera-stage",
].map((name) => [name, new FakeElement()]));
const video = elements.video;
video.videoWidth = 640;
video.videoHeight = 480;
video.readyState = 2;
video.play = async () => {};
video.pause = () => {};
video.requestVideoFrameCallback = (callback) => setTimeout(callback, 0);
video.cancelVideoFrameCallback = (handle) => clearTimeout(handle);
const modal = new FakeElement();
modal.querySelector = (selector) => elements[selector];
const body = new FakeElement();
body.appendChild = (item) => { document.currentModal = item; };
const document = new Emitter();
document.body = body;
document.hidden = false;
document.currentModal = null;
document.querySelector = () => document.currentModal;
document.createElement = (tag) => tag === "div" ? modal : {
  width: 0, height: 0,
  toBlob: (callback) => callback({ type: "image/jpeg", size: 1234 }),
  getContext: () => ({
    drawImage: () => {},
    putImageData: () => {},
    getImageData: (_x, _y, width, height) => ({
      width, height, data: new Uint8ClampedArray(width * height * 4),
    }),
  }),
};

const localValues = new Map();
const window = new Emitter();
window.location = { origin: "https://sqafe.com" };
window.isSecureContext = true;
window.devicePixelRatio = 1;
window.localStorage = {
  getItem: (key) => localValues.get(key) || null,
  setItem: (key, value) => localValues.set(key, value),
  removeItem: (key) => localValues.delete(key),
};

class Track {
  constructor(id) {
    this.id = id;
    this.readyState = "live";
    this.applied = [];
    this.onended = null;
  }
  getSettings() { return { deviceId: this.id, facingMode: this.id === "front" ? "user" : "environment" }; }
  getCapabilities() {
    return { zoom: { min: 1, max: 3 }, torch: true,
      focusMode: ["continuous", "single-shot"], exposureMode: ["continuous"], pointsOfInterest: true };
  }
  async applyConstraints(value) { this.applied.push(value); }
  stop() { this.readyState = "ended"; }
}

const mediaDevices = new Emitter();
const cameraCalls = [];
const tracks = [];
mediaDevices.getUserMedia = async (constraints) => {
  cameraCalls.push(constraints);
  if (cameraCalls.length === 1) throw Object.assign(new Error("resolution"), { name: "OverconstrainedError" });
  const id = constraints.video.deviceId?.exact || "rear-1";
  const track = new Track(id);
  tracks.push(track);
  return { getTracks: () => [track], getVideoTracks: () => [track] };
};
mediaDevices.enumerateDevices = async () => [
  { kind: "videoinput", deviceId: "rear-1", label: "Wide" },
  { kind: "videoinput", deviceId: "rear-2", label: "Telephoto" },
  { kind: "videoinput", deviceId: "front", label: "Front" },
];
const navigator = { mediaDevices };
let scenario = "single";
let captureRequests = 0;
let locateRequests = 0;

class Worker {
  constructor() { setTimeout(() => this.onmessage?.({ data: { type: "ready" } }), 0); }
  postMessage(request) {
    if (request.mode === "capture") captureRequests += 1;
    if (request.mode === "locate") locateRequests += 1;
    const payload = scenario === "ambiguous"
      ? (captureRequests % 2 === 1 ? "https://a.example" : "https://b.example")
      : "https://example.com";
    const quad = {
      topLeft: { x: 200, y: 140 }, topRight: { x: 430, y: 140 },
      bottomRight: { x: 430, y: 370 }, bottomLeft: { x: 200, y: 370 },
    };
    setTimeout(() => this.onmessage?.({ data: {
      id: request.id,
      symbols: request.mode === "capture"
        ? (scenario === "miss" ? [] : [{ valid: true, text: payload, quad }])
        : request.mode === "locate" && scenario === "auto" ? [{ valid: true, text: payload, quad }] : [],
      stats: { sharpness: 100 }, multipleCodes: false,
      width: 640, height: 480,
    } }), 0);
  }
  terminate() {}
}

vm.runInNewContext(code, { window, document, navigator, Worker, setTimeout, clearTimeout,
  Uint8ClampedArray, console });

async function eventually(test, label, attempts = 50) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (test()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

const results = [];
window.SafeScanQrCamera.open({ onResult: (payload) => results.push(payload) });
await eventually(() => !elements[".qr-camera-capture"].disabled, "camera preview");
assert.equal(cameraCalls[0].video.width.ideal, 1920);
assert.equal(cameraCalls[1].video.width.ideal, 1280);
assert.equal(cameraCalls[0].video.frameRate.ideal, 30);
assert.equal(elements[".qr-camera-switch"].hidden, false);
assert.equal(elements[".qr-camera-zoom"].hidden, false);
assert.equal(elements[".qr-camera-torch"].hidden, false);
assert.equal(video.classList.contains("is-mirrored"), false);
assert.equal(results.length, 0, "preview must not submit a QR payload");

await elements[".qr-camera-zoom"].dispatch("click");
assert.equal(tracks.at(-1).applied.at(-1).advanced[0].zoom, 2);
await elements[".qr-camera-torch"].dispatch("click");
assert.equal(tracks.at(-1).applied.at(-1).advanced[0].torch, true);
await video.dispatch("click", { clientX: 400, clientY: 240 });
assert.equal(tracks.at(-1).applied.at(-1).advanced[0].focusMode, "single-shot");

const firstTrack = tracks.at(-1);
await elements[".qr-camera-switch"].dispatch("click");
await eventually(() => tracks.at(-1).id === "rear-2" && !elements[".qr-camera-capture"].disabled, "camera switch");
assert.equal(firstTrack.readyState, "ended");
assert.equal(localValues.get("safescan-qr-camera-device:https://sqafe.com"), "rear-2");

const secondTrack = tracks.at(-1);
document.hidden = true;
await document.dispatch("visibilitychange");
assert.equal(secondTrack.readyState, "ended");
assert.equal(elements[".qr-camera-capture"].disabled, true);
document.hidden = false;
await document.dispatch("visibilitychange");
await eventually(() => !elements[".qr-camera-capture"].disabled, "camera resume");
assert.equal(tracks.at(-1).id, "rear-2");

tracks.at(-1).onended();
assert.equal(elements[".qr-camera-retry"].hidden, false);
await elements[".qr-camera-retry"].dispatch("click");
await eventually(() => !elements[".qr-camera-capture"].disabled, "camera retry");

await elements[".qr-camera-switch"].dispatch("click");
await eventually(() => tracks.at(-1).id === "front" && !elements[".qr-camera-capture"].disabled, "front camera switch");
assert.equal(video.classList.contains("is-mirrored"), true, "only the preview is mirrored");

await elements[".qr-camera-capture"].dispatch("click");
await eventually(() => results.length === 1, "deliberate capture result");
assert.equal(results[0], "https://example.com");
assert.equal(captureRequests, 6, "burst must inspect all six frames before accepting one code");
assert.equal(tracks.at(-1).readyState, "ended", "closing scanner stops camera");

scenario = "ambiguous";
const ambiguousResults = [];
let serverOffers = 0;
window.SafeScanQrCamera.open({ onResult: (payload) => ambiguousResults.push(payload),
  onServerFallback: () => { serverOffers += 1; return true; } });
await eventually(() => !elements[".qr-camera-capture"].disabled, "ambiguity preview");
await elements[".qr-camera-capture"].dispatch("click");
assert.equal(ambiguousResults.length, 0, "different burst payloads must refuse analysis");
assert.equal(elements[".qr-camera-server-offer"].hidden, true, "ambiguity must not offer server fallback");
assert.match(elements[".qr-camera-status"].textContent, /two QR codes/i);
assert.equal(serverOffers, 0);
await elements[".qr-camera-close"].dispatch("click");

scenario = "miss";
let sent = null;
window.SafeScanQrCamera.open({ onResult: () => assert.fail("miss submitted a payload"),
  onServerFallback: (blob) => { sent = blob; return true; } });
await eventually(() => !elements[".qr-camera-capture"].disabled, "fallback preview");
await elements[".qr-camera-capture"].dispatch("click");
assert.equal(sent, null, "no image should be sent without a separate click");
assert.equal(elements[".qr-camera-server-offer"].hidden, false);
await elements[".qr-camera-server-send"].dispatch("click");
assert.equal(sent.type, "image/jpeg");

scenario = "auto";
const autoResults = [];
window.SafeScanQrCamera.open({ onResult: (payload) => autoResults.push(payload) });
await eventually(() => !elements[".qr-camera-capture"].disabled, "auto preview");
assert.equal(elements[".qr-camera-auto"].attributes["aria-pressed"], "false", "auto-capture starts off");
await elements[".qr-camera-auto"].dispatch("click");
await eventually(() => autoResults.length === 1, "stable auto-capture", 300);
assert.equal(autoResults[0], "https://example.com");
assert.ok(locateRequests >= 3, "auto-capture needs repeated live observations");
console.log("Camera controls, burst consensus, consented fallback, and opt-in auto-capture: pass");
