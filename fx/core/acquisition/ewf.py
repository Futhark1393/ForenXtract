# Author: Futhark1393
# Description: EWF (E01) evidence writer.
# Gracefully unavailable when pyewf is not installed.

try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    pyewf = None
    EWF_AVAILABLE = False


class EwfWriter:
    """
    Wraps pyewf.handle with a uniform write/close interface.
    Raises RuntimeError if pyewf is not installed.
    """

    def __init__(self, filepath: str):
        if not EWF_AVAILABLE:
            raise RuntimeError(
                "pyewf is not installed. Cannot write E01 format. "
                "Install libewf and pyewf to enable EWF support."
            )
        # libewf determines the segment file type from the filename extension.
        # If the first segment has no .E01/.e01 extension, finalization can fail.
        if "." not in filepath:
            filepath = filepath + ".E01"
        self._handle = pyewf.handle()
        self._handle.open([filepath], "w")
        self._closed = False

    def write(self, chunk: bytes) -> None:
        self._handle.write_buffer(chunk)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._handle.close()
