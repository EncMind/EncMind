// Type declarations for the Javy WASM runtime.
declare namespace Javy {
  namespace IO {
    function readSync(fd: number, buffer: Uint8Array): number;
    function writeSync(fd: number, data: Uint8Array): void;
  }
}
