# Author: Futhark1393
# Description: RAW evidence writer.


class RawWriter:
    """Wraps a plain binary file with a uniform write/close interface."""

    def __init__(self, filepath: str):
        self._fh = open(filepath, "wb")

    def write(self, chunk: bytes) -> None:
        self._fh.write(chunk)

    def close(self) -> None:
        import os as _os
        self._fh.flush()
        _os.fsync(self._fh.fileno())
        self._fh.close()
