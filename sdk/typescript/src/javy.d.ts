// Type declarations for the Javy WASM runtime.
// These are provided by the Javy environment at runtime.

declare namespace Javy {
  namespace IO {
    /**
     * Read bytes into `buffer` from a file descriptor.
     * Returns the number of bytes read (0 = EOF).
     */
    function readSync(fd: number, buffer: Uint8Array): number;
    /** Write bytes to a file descriptor (1 = stdout, 2 = stderr). */
    function writeSync(fd: number, data: Uint8Array): void;
  }
}
