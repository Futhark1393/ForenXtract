#!/usr/bin/env python3
# Author: Futhark1393
# Description: CLI verifier for RFI forensic audit trails (JSONL hash chain).

import argparse
import os
import sys

from codes.logger import AuditChainVerifier


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rfi-verify",
        description="Verify RFI JSONL audit chain integrity (prev_hash -> entry_hash).",
    )
    p.add_argument(
        "audit_file",
        help="Path to AuditTrail_*.jsonl file",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Only print PASS/FAIL (no extra text).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    path = args.audit_file

    if not os.path.exists(path):
        if args.quiet:
            print("FAIL")
        else:
            print(f"FAIL: file not found: {path}")
        return 2

    try:
        ok, message = AuditChainVerifier.verify_chain(path)
    except Exception as e:
        if args.quiet:
            print("FAIL")
        else:
            print(f"ERROR: verifier crashed: {e}")
        return 1

    if ok:
        if args.quiet:
            print("PASS")
        else:
            print(f"PASS: {message}")
        return 0

    if args.quiet:
        print("FAIL")
    else:
        print(f"FAIL: {message}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
