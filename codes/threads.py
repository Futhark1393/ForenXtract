# Author: Futhark1393
# Description: Acquisition Worker thread.
# Features: Paramiko SSH stream, on-the-fly hashing, ETA, throttling, Safe Mode,
#          Live Triage, optional Write-Blocker enforcement, and post-acq hash verification.

import os
import time
import hashlib
from PyQt6.QtCore import QThread, pyqtSignal
import paramiko

# Optional libewf support
try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    EWF_AVAILABLE = False


class AcquisitionWorker(QThread):
    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        ip,
        user,
        key_path,
        disk,
        output_file,
        format_type,
        case_no,
        examiner,
        throttle_limit=0.0,
        safe_mode=True,
        run_triage=False,
        output_dir="",
        verify_hash=False,
        write_blocker=False,
    ):
        super().__init__()
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

        self._is_running = True
        self.chunk_size = 4 * 1024 * 1024  # 4 MB

    def stop(self):
        self._is_running = False

    def _ssh_exec(self, ssh: paramiko.SSHClient, cmd: str) -> tuple[str, str, int]:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        code = stdout.channel.recv_exit_status()
        return out.strip(), err.strip(), code

    def _apply_write_blocker(self, ssh: paramiko.SSHClient) -> None:
        """
        Best-effort software write-block.
        If this fails, we abort because verification against /dev requires immutability.
        """
        # 1) Try blockdev setro
        _, err, code = self._ssh_exec(ssh, f"sudo -n blockdev --setro {self.disk}")
        if code != 0:
            raise RuntimeError(f"Write-blocker failed (blockdev --setro). {err}")

        # 2) Validate read-only flag
        out, err, code = self._ssh_exec(ssh, f"sudo -n blockdev --getro {self.disk}")
        if code != 0:
            raise RuntimeError(f"Write-blocker check failed (blockdev --getro). {err}")

        # blockdev --getro returns "0" or "1"
        if out.strip() != "1":
            raise RuntimeError("Write-blocker check failed: device is not read-only (blockdev --getro != 1).")

        # 3) Optional hdparm read-only bit (best-effort, ignore failure)
        self._ssh_exec(ssh, f"sudo hdparm -r1 {self.disk}")

    def run(self):
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            total_bytes = 0
            target_bytes = 0
            start_time = time.time()

            # 1) Open local evidence output
            if self.format_type == "E01" and EWF_AVAILABLE:
                out_target = pyewf.handle()
                out_target.open([self.output_file], "w")
            else:
                out_target = open(self.output_file, "wb")

            retries = 0
            max_retries = 3
            success = False

            ssh = None

            while self._is_running and retries <= max_retries:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    if retries > 0:
                        self.progress_signal.emit(
                            {
                                "bytes_read": total_bytes,
                                "speed_mb_s": 0.0,
                                "md5_current": md5_hash.hexdigest(),
                                "percentage": int((total_bytes / target_bytes) * 100) if target_bytes > 0 else 0,
                                "eta": f"Connection lost. Retrying ({retries}/{max_retries})...",
                            }
                        )
                        time.sleep(3)

                    ssh.connect(self.ip, username=self.user, key_filename=self.key_path, timeout=10)

                    # One-time preflight: triage + size + (optional) write-blocker
                    if target_bytes == 0:
                        # Live triage before acquisition
                        if self.run_triage and self.output_dir:
                            self.progress_signal.emit(
                                {
                                    "bytes_read": 0,
                                    "speed_mb_s": 0.0,
                                    "md5_current": "",
                                    "percentage": 0,
                                    "eta": "Running Live Triage...",
                                }
                            )
                            triage_file_path = os.path.join(self.output_dir, f"Triage_{self.case_no}.txt")
                            try:
                                triage_script = (
                                    "echo '=== SYSTEM & DATE ==='; uname -a; date; uptime; "
                                    "echo '\n=== NETWORK CONNECTIONS ==='; ss -tulnp || netstat -tulnp; "
                                    "echo '\n=== RUNNING PROCESSES ==='; ps aux"
                                )
                                t_out, t_err, t_code = self._ssh_exec(ssh, f"sudo sh -c \"{triage_script}\"")
                                with open(triage_file_path, "w", encoding="utf-8") as tf:
                                    tf.write(t_out + "\n")
                                    if t_err:
                                        tf.write("\n--- STDERR ---\n" + t_err + "\n")
                            except Exception:
                                pass

                        # Get disk size
                        out, err, code = self._ssh_exec(ssh, f"sudo -n blockdev --getsize64 {self.disk}")
                        if code != 0 or not out.strip().isdigit():
                            raise RuntimeError(f"Failed to read disk size. {err}")
                        target_bytes = int(out.strip())

                        # Apply write-blocker if requested
                        if self.write_blocker:
                            self.progress_signal.emit(
                                {
                                    "bytes_read": 0,
                                    "speed_mb_s": 0.0,
                                    "md5_current": "",
                                    "percentage": 0,
                                    "eta": "Applying Write-Blocker...",
                                }
                            )
                            self._apply_write_blocker(ssh)

                    # dd flags
                    conv_flag = " conv=noerror,sync" if self.safe_mode else ""
                    # Continue from last byte using iflag=skip_bytes
                    command = f"sudo dd if={self.disk} bs=4M skip={total_bytes} iflag=skip_bytes{conv_flag} status=none"
                    stdin, stdout, stderr = ssh.exec_command(command)

                    while self._is_running:
                        chunk_start_time = time.time()

                        chunk = stdout.read(self.chunk_size)
                        if not chunk:
                            success = True
                            break

                        total_bytes += len(chunk)
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)

                        if self.format_type == "E01" and EWF_AVAILABLE:
                            out_target.write_buffer(chunk)
                        else:
                            out_target.write(chunk)

                        # Throttling
                        if self.throttle_limit > 0:
                            chunk_mb = len(chunk) / (1024 * 1024)
                            expected_time = chunk_mb / self.throttle_limit
                            actual_time = time.time() - chunk_start_time
                            if actual_time < expected_time:
                                time.sleep(expected_time - actual_time)

                        elapsed = time.time() - start_time
                        mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                        percentage = 0
                        eta_str = "Calculating..."
                        if target_bytes > 0:
                            percentage = int((total_bytes / target_bytes) * 100)
                            if mb_per_sec > 0:
                                bytes_per_sec = mb_per_sec * 1024 * 1024
                                remaining_bytes = max(0, target_bytes - total_bytes)
                                eta_seconds = remaining_bytes / bytes_per_sec
                                eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))

                        self.progress_signal.emit(
                            {
                                "bytes_read": total_bytes,
                                "speed_mb_s": round(mb_per_sec, 2),
                                "md5_current": md5_hash.hexdigest(),
                                "percentage": min(100, percentage),
                                "eta": eta_str,
                            }
                        )

                    # dd exit status check
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0 and self._is_running:
                        err_text = stderr.read().decode("utf-8", errors="ignore").strip()
                        raise RuntimeError(f"dd failed: {err_text}")

                    if success or not self._is_running:
                        break

                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        self.error_signal.emit(f"Network/acquisition failure. Max retries exceeded: {str(e)}")
                        break
                finally:
                    # Keep ssh open for verify phase when success+verify_hash
                    if ssh and not (success and self.verify_hash):
                        ssh.close()

            out_target.close()

            # Post-Acquisition Hash Verification
            remote_sha256 = "SKIPPED"
            hash_match = None

            if success and self._is_running and self.verify_hash:
                self.progress_signal.emit(
                    {
                        "bytes_read": total_bytes,
                        "speed_mb_s": 0.0,
                        "md5_current": md5_hash.hexdigest(),
                        "percentage": 100,
                        "eta": "Verifying Source Hash (Please Wait)...",
                    }
                )

                try:
                    # IMPORTANT:
                    # This compares source disk hash to the STREAM hash (sha256_hash) — not the E01 container hash.
                    # It will still mismatch if the disk changes after imaging (write-blocker strongly recommended).
                    out, err, code = self._ssh_exec(ssh, f"sudo -n sha256sum {self.disk}")
                    if code != 0 or not out:
                        remote_sha256 = "ERROR"
                        hash_match = False
                    else:
                        remote_sha256 = out.split()[0]
                        hash_match = (remote_sha256 == sha256_hash.hexdigest())
                except Exception:
                    remote_sha256 = "ERROR"
                    hash_match = False
                finally:
                    if ssh:
                        ssh.close()

            if success and self._is_running:
                self.finished_signal.emit(
                    {
                        "sha256_final": sha256_hash.hexdigest(),
                        "md5_final": md5_hash.hexdigest(),
                        "total_bytes": total_bytes,
                        "remote_sha256": remote_sha256,
                        "hash_match": hash_match,
                    }
                )
            elif not self._is_running:
                self.error_signal.emit("Process aborted by user.")

        except Exception as e:
            self.error_signal.emit(f"Initialization Error: {str(e)}")
