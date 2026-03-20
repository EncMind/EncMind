/**
 * Javy ABI runtime bridge for EncMind WASM skills.
 *
 * Protocol (Javy ABI):
 *   1. Host writes JSON input to WASI stdin
 *   2. Host calls `_start()`
 *   3. Guest reads stdin via `Javy.IO.readSync(fd, buffer)` until EOF
 *   4. Guest dispatches to the registered handler
 *   5. Guest writes JSON output to stdout via `Javy.IO.writeSync(1, data)`
 *   6. Host reads stdout to get the response
 *
 * Limits:
 *   - stdin payload max: 16 MiB
 *   - stdout payload max: enforced by host (currently 1 MiB)
 */

/// <reference path="./javy.d.ts" />

// The registered handler — set by registerTool() in index.ts
let _handler: ((input: unknown) => unknown) | null = null;
// Note: single underscore prefix — "__encmind" (double) triggers a QuickJS
// atom-table bug in Javy 3.0 that corrupts Uint8Array type checks.
const RUNTIME_ENVELOPE_KEY = "_encmind";
const RUNTIME_ERROR_KEY = "runtime_error";
const MAX_STDIN_BYTES = 16 * 1024 * 1024; // 16 MiB (must match host limit)

function writeJson(value: unknown): void {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("handler returned a non-JSON-serializable value");
  }
  const encoded = new TextEncoder().encode(json);
  Javy.IO.writeSync(1, encoded);
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function writeRuntimeError(message: string): void {
  writeJson({
    [RUNTIME_ENVELOPE_KEY]: {
      [RUNTIME_ERROR_KEY]: message,
    },
  });
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
      throw new Error(`Javy.IO.readSync returned invalid byte count: ${read}`);
    }
    if (read === 0) {
      break;
    }
    if (total + read > MAX_STDIN_BYTES) {
      throw new Error(
        `stdin payload too large: ${total + read} bytes (max ${MAX_STDIN_BYTES})`,
      );
    }
    const slice = read === chunkSize ? chunk : chunk.slice(0, read);
    chunks.push(slice);
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

/**
 * Register the tool handler that main() will dispatch to.
 */
export function setHandler(handler: (input: unknown) => unknown): void {
  _handler = handler;
}

/**
 * Main entry point — called at module load time.
 *
 * Reads JSON from stdin, dispatches to the registered handler,
 * and writes the JSON result to stdout.
 */
export function main(): void {
  try {
    if (!_handler) {
      writeRuntimeError("no handler registered");
      return;
    }

    // Read input from stdin
    const inputBytes = readAll(0);
    const inputStr = new TextDecoder().decode(inputBytes);
    const input = JSON.parse(inputStr);

    // Dispatch to handler
    const output = _handler(input);
    if (output instanceof Promise) {
      throw new Error("Async tool handlers are not supported in WASM skills");
    }
    writeJson(output);
  } catch (err) {
    writeRuntimeError(errorMessage(err));
  }
}
