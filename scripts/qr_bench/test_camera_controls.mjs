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
  getBoundingClientRect() { return { left: 0, top: 0, width: 640, height: 480 }; }
  remove() { document.currentModal = null; }
}

const elements = Object.fromEntries([
  "video", ".qr-camera-status", ".qr-camera-close", ".qr-camera-capture",
  ".qr-camera-controls", ".qr-camera-switch", ".qr-camera-zoom",
  ".qr-camera-torch", ".qr-camera-retry",
].map((name) => [name, new FakeElement()]));
const video = elements.video;
video.videoWidth = 640;
video.videoHeight = 480;
video.readyState = 2;
video.play = async () => {};
video.pause = () => {};
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
  getContext: () => ({
    drawImage: () => {},
    getImageData: (_x, _y, width, height) => ({
      width, height, data: new Uint8ClampedArray(width * height * 4),
    }),
  }),
};

const localValues = new Map();
const window = new Emitter();
window.location = { origin: "https://sqafe.com" };
window.isSecureContext = true;
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

class Worker {
  constructor() { setTimeout(() => this.onmessage?.({ data: { type: "ready" } }), 0); }
  postMessage(request) {
    setTimeout(() => this.onmessage?.({ data: {
      id: request.id, symbols: [{ valid: true, text: "https://example.com" }], multipleCodes: false,
    } }), 0);
  }
  terminate() {}
}

vm.runInNewContext(code, { window, document, navigator, Worker, setTimeout, clearTimeout,
  Uint8ClampedArray, console });

async function eventually(test, label) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
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
assert.equal(tracks.at(-1).readyState, "ended", "closing scanner stops camera");
console.log("Camera resolution fallback, controls, switch, lifecycle, and capture: pass");
