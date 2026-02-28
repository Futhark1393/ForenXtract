# Author: Futhark1393
# Description: Post-acquisition remote hash verification.

import re
import shlex

import paramiko

from fx.core.policy import ssh_exec


def _validate_disk_path(disk: str) -> None:
    """Reject obviously malicious device paths to prevent command injection."""
    if not re.match(r"^/dev/[a-zA-Z0-9/_-]+$", disk):
        raise ValueError(f"Invalid disk path: {disk!r}")


def verify_source_hash(
    ssh: paramiko.SSHClient, disk: str
) -> tuple[str, bool | None]:
    """
    Compute SHA-256 of the source disk on the remote host and compare
    against the local stream hash.

    Returns (remote_sha256, matched_or_none).
    On error, returns ("ERROR", False).
    """
    try:
        _validate_disk_path(disk)
        out, err, code = ssh_exec(ssh, f"sudo -n sha256sum {shlex.quote(disk)}")
        if code != 0 or not out:
            return "ERROR", False
        remote_sha256 = out.split()[0]
        return remote_sha256, None  # caller compares against local hash
    except Exception:
        return "ERROR", False
