// EncMind Skill: Plugin Smoke Test (TypeScript / Javy ABI)
//
// Exercises the Javy stdin/stdout tool-only path with multiple modes:
//   - default: echo input
//   - upper:   uppercase the message
//   - reverse: reverse the message
//
// Build:
//   npm install
//   npx tsc && javy compile dist/index.js -o plugin-smoke-javy.wasm
//   # or: encmind-skill build .

/// <reference path="./javy.d.ts" />

interface ToolInput {
  message?: string;
  mode?: string;
  [key: string]: unknown;
}

interface ToolOutput {
  result: string;
}

function handle(input: ToolInput): ToolOutput {
  var msg = input.message || "";
  switch (input.mode) {
    case "upper":
      return { result: msg.toUpperCase() };
    case "reverse":
      return { result: msg.split("").reverse().join("") };
    default:
      return { result: "echo: " + msg };
  }
}

function stringToBytes(s: string): Uint8Array {
  var buf = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) {
    buf[i] = s.charCodeAt(i) & 0xff;
  }
  return buf;
}

const MAX_STDIN_BYTES = 16 * 1024 * 1024; // 16 MiB (must match host limit)

function readAll(fd: number): Uint8Array {
  var chunkSize = 8192;
  var chunks: Uint8Array[] = [];
  var total = 0;
  while (true) {
    var chunk = new Uint8Array(chunkSize);
    var read = Javy.IO.readSync(fd, chunk);
    if (
      typeof read !== "number" ||
      read < 0 ||
      read > chunkSize ||
      (read | 0) !== read
    ) {
      throw new Error("Javy.IO.readSync returned invalid byte count: " + String(read));
    }
    if (read === 0) {
      break;
    }
    if (total + read > MAX_STDIN_BYTES) {
      throw new Error("stdin payload too large: " + String(total + read) + " bytes (max " + String(MAX_STDIN_BYTES) + ")");
    }
    var slice = read === chunkSize ? chunk : chunk.slice(0, read);
    chunks.push(slice);
    total += read;
  }
  var output = new Uint8Array(total);
  var offset = 0;
  for (var i = 0; i < chunks.length; i++) {
    output.set(chunks[i], offset);
    offset += chunks[i].length;
  }
  return output;
}

function escapeJsonString(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

function writeOutput(value: unknown): void {
  var json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("handler returned a non-JSON-serializable value");
  }
  Javy.IO.writeSync(1, stringToBytes(json));
}

// Javy ABI: read stdin -> process -> write stdout
try {
  var inputBytes = readAll(0);
  var inputStr = "";
  for (var i = 0; i < inputBytes.length; i++) {
    inputStr += String.fromCharCode(inputBytes[i]);
  }
  var input: ToolInput = JSON.parse(inputStr);
  var output = handle(input);
  writeOutput(output);
} catch (err) {
  // Workaround: Javy 3.0 QuickJS bug — calling JSON.stringify anywhere in the
  // catch block (even dead code) corrupts the try block's writeOutput call.
  // Construct the error JSON manually via string concatenation.
  var errStr = (err instanceof Error) ? err.message : String(err);
  // Note: single underscore "_encmind" — double "__encmind" triggers a
  // QuickJS atom-table bug in Javy 3.0.
  var errJson = '{"_encmind":{"runtime_error":"' + escapeJsonString(errStr) + '"}}';
  Javy.IO.writeSync(1, stringToBytes(errJson));
}
