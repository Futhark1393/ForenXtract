#!/usr/bin/env python3
# Author: Futhark1393
# Backward-compatibility shim for rfi_verify.py (root-level).
# Logic has moved to rfi.cli.verify. This file delegates to it.

from rfi.cli.verify import main

if __name__ == "__main__":
    raise SystemExit(main())
