// EncMind Skill: Echo (TypeScript / Javy ABI)
//
// Demonstrates the Javy ABI: reads JSON from stdin, writes JSON to stdout.
//
// Build:
//   npm install
//   npx tsc && javy compile dist/index.js -o echo-ts.wasm
//   # or: encmind-skill build .

/// <reference path="./javy.d.ts" />

interface ToolInput {
  message?: string;
  [key: string]: unknown;
}

interface ToolOutput {
  result: string;
}

function handle(input: ToolInput): ToolOutput {
  return {
    result: `echo: ${JSON.stringify(input)}`,
  };
}

const RUNTIME_ENVELOPE_KEY = "_encmind";
const RUNTIME_ERROR_KEY = "runtime_error";
const MAX_STDIN_BYTES = 16 * 1024 * 1024; // 16 MiB (must match host limit)

function writeJson(value: unknown): void {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("handler returned a non-JSON-serializable value");
  }
  Javy.IO.writeSync(1, new TextEncoder().encode(json));
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function readAll(fd: number): Uint8Array {
  const chunkSize = 8192;
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const chunk = new Uint8Array(chunkSize);
    const read = Javy.IO.readSync(fd, chunk);
    if (
      typeof read !== "number" ||
      read < 0 ||
      read > chunkSize ||
      (read | 0) !== read
    ) {
      throw new Error(`Javy.IO.readSync returned invalid byte count: ${String(read)}`);
    }
    if (read === 0) {
      break;
    }
    if (total + read > MAX_STDIN_BYTES) {
      throw new Error(`stdin payload too large: ${total + read} bytes (max ${MAX_STDIN_BYTES})`);
    }
    chunks.push(read === chunkSize ? chunk : chunk.slice(0, read));
    total += read;
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

// Javy ABI: read stdin → process → write stdout
try {
  const inputBytes = readAll(0);
  const input: ToolInput = JSON.parse(new TextDecoder().decode(inputBytes));
  const output = handle(input);
  writeJson(output);
} catch (err) {
  writeJson({
    [RUNTIME_ENVELOPE_KEY]: {
      [RUNTIME_ERROR_KEY]: errorMessage(err),
    },
  });
}
