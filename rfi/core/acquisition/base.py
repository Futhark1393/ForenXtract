# Author: Futhark1393
# Description: Pure-Python acquisition engine — no Qt dependency.
# Features: SSH streaming, on-the-fly hashing, ETA, throttling, resume-on-disconnect,
#          live triage, optional write-blocker, and post-acquisition hash verification.

import os
import time
from typing import Callable

import paramiko

from rfi.core.hashing import StreamHasher
from rfi.core.policy import ssh_exec, apply_write_blocker, build_dd_command
from rfi.core.acquisition.raw import RawWriter
from rfi.core.acquisition.ewf import EwfWriter, EWF_AVAILABLE
from rfi.core.acquisition.verify import verify_source_hash


class AcquisitionError(Exception):
    """Raised on unrecoverable acquisition failure."""
    pass


class AcquisitionEngine:
    """
    Pure-Python forensic acquisition engine. No Qt imports.

    Progress is reported via an ``on_progress(data: dict)`` callback so
    the caller (Qt worker, CLI tool, test harness) can handle it however
    it likes.
    """

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB
    MAX_RETRIES = 3

    def __init__(
        self,
        ip: str,
        user: str,
        key_path: str,
        disk: str,
        output_file: str,
        format_type: str,
        case_no: str,
        examiner: str,
        throttle_limit: float = 0.0,
        safe_mode: bool = True,
        run_triage: bool = False,
        output_dir: str = "",
        verify_hash: bool = False,
        write_blocker: bool = False,
        on_progress: Callable[[dict], None] | None = None,
    ):
        self.ip = ip
        self.user = user
        self.key_path = key_path
        self.disk = disk
        self.output_file = output_file
        self.format_type = format_type
        self.case_no = case_no
        self.examiner = examiner
        self.throttle_limit = throttle_limit
        self.safe_mode = safe_mode
        self.run_triage = run_triage
        self.output_dir = output_dir
        self.verify_hash = verify_hash
        self.write_blocker = write_blocker
        self.on_progress = on_progress or (lambda d: None)

        self._is_running = True

    def stop(self) -> None:
        """Request a graceful stop of the acquisition loop."""
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    # ── Progress helper ─────────────────────────────────────────────────

    def _emit(self, bytes_read: int, speed: float, md5: str, pct: int, eta: str) -> None:
        self.on_progress({
            "bytes_read": bytes_read,
            "speed_mb_s": round(speed, 2),
            "md5_current": md5,
            "percentage": min(100, pct),
            "eta": eta,
        })

    # ── Triage ──────────────────────────────────────────────────────────

    def _run_triage(self, ssh: paramiko.SSHClient) -> None:
        if not (self.run_triage and self.output_dir):
            return

        self._emit(0, 0.0, "", 0, "Running Live Triage...")
        triage_path = os.path.join(self.output_dir, f"Triage_{self.case_no}.txt")
        try:
            triage_script = (
                "echo '=== SYSTEM & DATE ==='; uname -a; date; uptime; "
                "echo '\\n=== NETWORK CONNECTIONS ==='; ss -tulnp || netstat -tulnp; "
                "echo '\\n=== RUNNING PROCESSES ==='; ps aux"
            )
            t_out, t_err, _ = ssh_exec(ssh, f'sudo sh -c "{triage_script}"')
            with open(triage_path, "w", encoding="utf-8") as tf:
                tf.write(t_out + "\n")
                if t_err:
                    tf.write("\n--- STDERR ---\n" + t_err + "\n")
        except Exception:
            pass  # triage is best-effort

    # ── Main loop ───────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Execute the full acquisition pipeline.

        Returns a dict on success:
            sha256_final, md5_final, total_bytes, remote_sha256, hash_match

        Raises AcquisitionError on failure.
        """
        hasher = StreamHasher()
        total_bytes = 0
        target_bytes = 0
        start_time = time.time()

        # Open evidence writer
        if self.format_type == "E01" and EWF_AVAILABLE:
            writer = EwfWriter(self.output_file)
        else:
            writer = RawWriter(self.output_file)

        retries = 0
        success = False
        ssh = None

        try:
            while self._is_running and retries <= self.MAX_RETRIES:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    if retries > 0:
                        pct = int((total_bytes / target_bytes) * 100) if target_bytes > 0 else 0
                        self._emit(total_bytes, 0.0, hasher.md5_hex, pct,
                                   f"Connection lost. Retrying ({retries}/{self.MAX_RETRIES})...")
                        time.sleep(3)

                    ssh.connect(self.ip, username=self.user, key_filename=self.key_path, timeout=10)

                    # One-time preflight
                    if target_bytes == 0:
                        self._run_triage(ssh)

                        out, err, code = ssh_exec(ssh, f"sudo -n blockdev --getsize64 {self.disk}")
                        if code != 0 or not out.strip().isdigit():
                            raise AcquisitionError(f"Failed to read disk size. {err}")
                        target_bytes = int(out.strip())

                        if self.write_blocker:
                            self._emit(0, 0.0, "", 0, "Applying Write-Blocker...")
                            apply_write_blocker(ssh, self.disk)

                    # Start dd
                    command = build_dd_command(self.disk, total_bytes, self.safe_mode)
                    stdin_ch, stdout_ch, stderr_ch = ssh.exec_command(command)

                    while self._is_running:
                        chunk_start = time.time()
                        chunk = stdout_ch.read(self.CHUNK_SIZE)
                        if not chunk:
                            success = True
                            break

                        total_bytes += len(chunk)
                        hasher.update(chunk)
                        writer.write(chunk)

                        # Throttling
                        if self.throttle_limit > 0:
                            chunk_mb = len(chunk) / (1024 * 1024)
                            expected = chunk_mb / self.throttle_limit
                            actual = time.time() - chunk_start
                            if actual < expected:
                                time.sleep(expected - actual)

                        elapsed = time.time() - start_time
                        mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                        pct = 0
                        eta_str = "Calculating..."
                        if target_bytes > 0:
                            pct = int((total_bytes / target_bytes) * 100)
                            if mb_per_sec > 0:
                                remaining = max(0, target_bytes - total_bytes)
                                eta_seconds = remaining / (mb_per_sec * 1024 * 1024)
                                eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))

                        self._emit(total_bytes, mb_per_sec, hasher.md5_hex, pct, eta_str)

                    # Check dd exit status
                    exit_status = stdout_ch.channel.recv_exit_status()
                    if exit_status != 0 and self._is_running:
                        err_text = stderr_ch.read().decode("utf-8", errors="ignore").strip()
                        raise AcquisitionError(f"dd failed: {err_text}")

                    if success or not self._is_running:
                        break

                except AcquisitionError:
                    raise
                except Exception as e:
                    retries += 1
                    if retries > self.MAX_RETRIES:
                        raise AcquisitionError(
                            f"Network/acquisition failure. Max retries exceeded: {e}"
                        )
                finally:
                    if ssh and not (success and self.verify_hash):
                        ssh.close()

            writer.close()

            # Post-acquisition hash verification
            remote_sha256 = "SKIPPED"
            hash_match = None

            if success and self._is_running and self.verify_hash:
                self._emit(total_bytes, 0.0, hasher.md5_hex, 100,
                           "Verifying Source Hash (Please Wait)...")
                try:
                    remote_sha256, _ = verify_source_hash(ssh, self.disk)
                    if remote_sha256 not in ("ERROR",):
                        hash_match = (remote_sha256 == hasher.sha256_hex)
                    else:
                        hash_match = False
                finally:
                    if ssh:
                        ssh.close()

            if not self._is_running:
                raise AcquisitionError("Process aborted by user.")

            if not success:
                raise AcquisitionError("Acquisition did not complete successfully.")

            return {
                "sha256_final": hasher.sha256_hex,
                "md5_final": hasher.md5_hex,
                "total_bytes": total_bytes,
                "remote_sha256": remote_sha256,
                "hash_match": hash_match,
            }

        except AcquisitionError:
            writer.close()
            raise
        except Exception as e:
            writer.close()
            raise AcquisitionError(f"Initialization Error: {e}")
