// Javy runtime global I/O
declare namespace Javy {
  namespace IO {
    /**
     * Synchronously read bytes from a file descriptor into a buffer.
     * Returns the number of bytes read, or 0 on EOF.
     */
    function readSync(fd: number, buffer: Uint8Array): number;

    /**
     * Synchronously write bytes to a file descriptor.
     */
    function writeSync(fd: number, data: Uint8Array): void;
  }
}
