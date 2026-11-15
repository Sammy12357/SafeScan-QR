const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "../static/server-error-focus.js"), "utf8");

function run({ marker = true, fields = [], readyState = "loading" } = {}) {
  const handlers = new Map();
  const document = {
    readyState,
    activeElement: { id: "body" },
    querySelector(selector) {
      assert.equal(selector, "[data-server-error-focus]");
      return marker ? summary : null;
    },
    querySelectorAll(selector) {
      assert.equal(selector, '[aria-invalid="true"]');
      return fields;
    },
    addEventListener(name, handler, options) {
      assert.equal(options.once, true);
      handlers.set(name, handler);
    },
  };
  const summary = {
    tabIndex: null,
    hasAttribute: () => false,
    focus() { document.activeElement = this; },
  };
  vm.runInNewContext(script, { document });
  if (handlers.has("DOMContentLoaded")) handlers.get("DOMContentLoaded")();
  return { document, summary };
}

function field({ disabled = false, hidden = false, visible = true } = {}) {
  return {
    disabled,
    closest(selector) {
      assert.equal(selector, "[hidden], [inert]");
      return hidden ? {} : null;
    },
    getClientRects() { return visible ? [{}] : []; },
    focus() { this.focused = true; },
  };
}

test("focuses the first visible invalid field after a server validation response", () => {
  const disabled = field({ disabled: true });
  const hidden = field({ hidden: true });
  const invalid = field();
  run({ fields: [disabled, hidden, invalid, field()] });
  assert.equal(invalid.focused, true);
  assert.equal(disabled.focused, undefined);
  assert.equal(hidden.focused, undefined);
});

test("focuses the summary when the rejected action has no field error", () => {
  const { document, summary } = run({ fields: [field({ visible: false })], readyState: "complete" });
  assert.equal(document.activeElement, summary);
  assert.equal(summary.tabIndex, -1);
});

test("leaves focus alone when the server returned no error marker", () => {
  const { document } = run({ marker: false, fields: [field()] });
  assert.equal(document.activeElement.id, "body");
});
