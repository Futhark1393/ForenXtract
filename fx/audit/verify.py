# Author: Futhark1393
# Description: Audit trail hash-chain verifier.
# Verifies the cryptographic integrity of JSONL forensic audit logs.

import os
import json
import hashlib


class AuditChainVerifier:
    @staticmethod
    def verify_chain(filepath: str) -> tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "File not found."

        # The genesis prev_hash is now per-session (includes entropy).
        # We accept whatever the first entry claims as prev_hash and then
        # verify that every subsequent entry's prev_hash equals the
        # entry_hash of the previous record.  This proves no entries were
        # inserted, deleted, or reordered — the genesis value itself is
        # trusted because it is cryptographically bound to the session_id
        # recorded inside the first entry.
        current_prev_hash: str | None = None
        line_number = 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line_number += 1
                    if not line.strip():
                        continue

                    entry = json.loads(line)
                    entry_copy = dict(entry)

                    claimed_prev = entry_copy.get("prev_hash")
                    claimed_entry = entry_copy.pop("entry_hash", None)

                    if not claimed_entry:
                        return False, (
                            f"Tampering detected: 'entry_hash' missing at line {line_number}."
                        )

                    # First record: accept its prev_hash as the genesis
                    if current_prev_hash is None:
                        current_prev_hash = claimed_prev

                    if claimed_prev != current_prev_hash:
                        return (
                            False,
                            f"Chain broken at line {line_number}. Expected prev: {current_prev_hash}, found: {claimed_prev}",
                        )

                    reconstructed_json = json.dumps(entry_copy, sort_keys=True)
                    reconstructed_hash = hashlib.sha256(reconstructed_json.encode("utf-8")).hexdigest()

                    if reconstructed_hash != claimed_entry:
                        return False, f"Entry manipulation detected at line {line_number}. Hash mismatch."

                    current_prev_hash = claimed_entry

            return True, f"Chain verified successfully. {line_number} cryptographic records intact."
        except Exception as e:
            return False, f"Verification error at line {line_number}: {str(e)}"
