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
        # pyewf/libewf appends segment extensions (.E01, .E02, …) automatically.
        # Strip any pre-existing EWF segment extension to prevent double suffixes
        # like "evidence.E01.E01" which breaks Autopsy / EnCase import.
        import re
        filepath = re.sub(r'\.[Ee]\d{2}$', '', filepath)
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
