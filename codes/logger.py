# Author: Futhark1393
# Description: Forensic-Grade Structured Logging Engine.
# Features: Cryptographic Hash Chaining, Thread-Safety, Kernel Sync (fsync),
#          Real File Sealing, and Defensive Chain Verification.

import os
import sys
import json
import uuid
import re
import hashlib
import subprocess
import threading
import shutil
from datetime import datetime, timezone


class ForensicLoggerError(Exception):
    pass


class ForensicLogger:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.case_no = "UNASSIGNED"
        self.examiner = "UNASSIGNED"
        self.output_dir = None

        self._lock = threading.Lock()
        self.log_file_path = f"temp_audit_{self.session_id}.jsonl"
        self.prev_hash = hashlib.sha256(b"FORENSIC_GENESIS_BLOCK").hexdigest()
        self._is_sealed = False

    def sanitize_filename(self, name: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(name).strip())
        return clean if clean else "UNASSIGNED"

    def set_context(self, case_no: str, examiner: str, output_dir: str) -> None:
        with self._lock:
            if self._is_sealed:
                raise ForensicLoggerError("Audit trail is sealed. Cannot modify context.")

            if not os.path.isdir(output_dir):
                raise ForensicLoggerError(f"Output directory does not exist: {output_dir}")
            if not os.access(output_dir, os.W_OK):
                raise ForensicLoggerError(f"Output directory lacks write permissions: {output_dir}")

            self.case_no = self.sanitize_filename(case_no)
            self.examiner = self.sanitize_filename(examiner)
            self.output_dir = output_dir

            new_log_path = os.path.join(
                self.output_dir, f"AuditTrail_{self.case_no}_{self.session_id}.jsonl"
            )

            try:
                if os.path.exists(self.log_file_path):
                    shutil.move(self.log_file_path, new_log_path)

                self.log_file_path = new_log_path

                # Log context binding explicitly as coming from the logger module.
                self._internal_log_unlocked(
                    "Session context successfully bound to evidence directory.",
                    "INFO",
                    "CONTEXT_UPDATED",
                    source_module="logger",
                )
            except OSError as e:
                raise ForensicLoggerError(
                    f"Failed to migrate audit trail to evidence directory: {str(e)}"
                )

    def log(
        self,
        message: str,
        level: str = "INFO",
        event_type: str = "GENERAL",
        source_module: str = "gui",
        hash_context: dict | None = None,
    ) -> str:
        with self._lock:
            return self._internal_log_unlocked(message, level, event_type, source_module, hash_context)

    def _internal_log_unlocked(
        self,
        message: str,
        level: str,
        event_type: str,
        source_module: str,
        hash_context: dict | None = None,
    ) -> str:
        if self._is_sealed:
            raise ForensicLoggerError(
                f"Audit log is mathematically sealed. Attempted to append: {message}"
            )

        now_utc = datetime.now(timezone.utc)
        timestamp_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        event_id = str(uuid.uuid4())

        log_entry = {
            "timestamp": timestamp_iso,
            "session_id": self.session_id,
            "case_no": self.case_no,
            "examiner": self.examiner,
            "event_id": event_id,
            "event_type": event_type,
            "severity": level,
            "source_module": source_module,
            "message": message,
        }

        if hash_context:
            log_entry["hash_context"] = hash_context

        self._write_to_file(log_entry)
        return f"[{timestamp_iso}] [{level}] {message}"

    def _write_to_file(self, log_entry: dict) -> None:
        try:
            log_entry["prev_hash"] = self.prev_hash

            # Compute entry hash deterministically (without entry_hash present).
            entry_json = json.dumps(log_entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

            log_entry["entry_hash"] = entry_hash
            self.prev_hash = entry_hash

            final_json = json.dumps(log_entry, sort_keys=True)

            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(final_json + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            raise ForensicLoggerError(f"File System Write Error: {str(e)}")

    def seal_audit_trail(self) -> tuple[str, bool]:
        with self._lock:
            if not self.log_file_path or not os.path.exists(self.log_file_path):
                return "UNAVAILABLE", False

            # IMPORTANT: provide source_module to match the method signature.
            self._internal_log_unlocked(
                "Initiating cryptographic seal of audit trail.",
                "INFO",
                "AUDIT_SEALING",
                source_module="logger",
            )

            # After this point, no further log() calls are allowed.
            self._is_sealed = True

            hasher = hashlib.sha256()
            try:
                with open(self.log_file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                final_hash = hasher.hexdigest()

                # Make read-only (best-effort). Immutable flag may fail without privilege.
                os.chmod(self.log_file_path, 0o444)

                chattr_success = False
                try:
                    subprocess.run(
                        ["sudo", "-n", "chattr", "+i", self.log_file_path],
                        check=True,
                        capture_output=True,
                    )
                    chattr_success = True
                except subprocess.CalledProcessError:
                    chattr_success = False

                return final_hash, chattr_success

            except OSError as e:
                print(f"CRITICAL: Failed to seal audit trail: {e}", file=sys.stderr)
                return "ERROR_CALCULATING_HASH", False


class AuditChainVerifier:
    @staticmethod
    def verify_chain(filepath: str) -> tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "File not found."

        current_prev_hash = hashlib.sha256(b"FORENSIC_GENESIS_BLOCK").hexdigest()
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
