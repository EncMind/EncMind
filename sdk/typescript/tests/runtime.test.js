import test from "node:test";
import assert from "node:assert/strict";

const runtimeModule = process.env.ENCMIND_SDK_RUNTIME_MODULE ?? "../src/runtime.ts";
const written = [];
let stdinBytes = new Uint8Array();
let stdinOffset = 0;

function resetStdin(payload = { name: "test", input: {} }) {
  stdinBytes = new TextEncoder().encode(JSON.stringify(payload));
  stdinOffset = 0;
}

function resetRawStdin(bytes) {
  stdinBytes = bytes;
  stdinOffset = 0;
}

globalThis.Javy = {
  IO: {
    readSync(_fd, buffer) {
      if (!(buffer instanceof Uint8Array)) {
        throw new TypeError("Data needs to be an Uint8Array");
      }
      if (stdinOffset >= stdinBytes.length) {
        return 0;
      }
      const remaining = stdinBytes.length - stdinOffset;
      const count = Math.min(buffer.length, remaining);
      buffer.set(stdinBytes.subarray(stdinOffset, stdinOffset + count));
      stdinOffset += count;
      return count;
    },
    writeSync(_fd, data) {
      written.push(new TextDecoder().decode(data));
    },
  },
};

const runtime = await import(runtimeModule);

test("runtime emits reserved envelope on handler failure", () => {
  resetStdin();
  written.length = 0;
  runtime.setHandler(() => {
    throw new Error("boom");
  });
  runtime.main();
  assert.equal(written.length, 1);
  const payload = JSON.parse(written[0]);
  assert.deepEqual(payload, { _encmind: { runtime_error: "boom" } });
});

test("runtime writes handler output on success", () => {
  resetStdin();
  written.length = 0;
  runtime.setHandler(() => ({ result: "ok" }));
  runtime.main();
  assert.equal(written.length, 1);
  const payload = JSON.parse(written[0]);
  assert.deepEqual(payload, { result: "ok" });
});

test("runtime emits error envelope for async handlers", () => {
  resetStdin();
  written.length = 0;
  runtime.setHandler(async () => ({ result: "ok" }));
  runtime.main();
  assert.equal(written.length, 1);
  const payload = JSON.parse(written[0]);
  assert.deepEqual(payload, {
    _encmind: { runtime_error: "Async tool handlers are not supported in WASM skills" },
  });
});

test("runtime emits error envelope for non-JSON-serializable output", () => {
  resetStdin();
  written.length = 0;
  runtime.setHandler(() => undefined);
  runtime.main();
  assert.equal(written.length, 1);
  const payload = JSON.parse(written[0]);
  assert.deepEqual(payload, {
    _encmind: { runtime_error: "handler returned a non-JSON-serializable value" },
  });
});

test("runtime emits error envelope when stdin exceeds max size", () => {
  resetRawStdin(new Uint8Array((16 * 1024 * 1024) + 1));
  written.length = 0;
  runtime.setHandler(() => ({ result: "ok" }));
  runtime.main();
  assert.equal(written.length, 1);
  const payload = JSON.parse(written[0]);
  assert.equal(typeof payload._encmind?.runtime_error, "string");
  assert.match(payload._encmind.runtime_error, /stdin payload too large/);
});
