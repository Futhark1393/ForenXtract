# Tests for rfi core modules: Session, StreamHasher, RawWriter, policy helpers.

import hashlib
import os
import tempfile
import pytest

from rfi.core.session import Session, SessionState, SessionStateError
from rfi.core.hashing import StreamHasher
from rfi.core.acquisition.raw import RawWriter
from rfi.core.policy import build_dd_command


# ═══════════════════════════════════════════════════════════════════════
# Session state machine tests
# ═══════════════════════════════════════════════════════════════════════

class TestSession:
    def test_initial_state_is_new(self):
        s = Session()
        assert s.state == SessionState.NEW

    def test_happy_path_full_workflow(self):
        s = Session()
        s.bind_context("CASE-001", "Investigator", "/tmp/evidence")
        assert s.state == SessionState.CONTEXT_BOUND
        assert s.case_no == "CASE-001"

        s.begin_acquisition()
        assert s.state == SessionState.ACQUIRING

        s.begin_verification()
        assert s.state == SessionState.VERIFYING

        s.seal()
        assert s.state == SessionState.SEALED

        s.finalize()
        assert s.state == SessionState.DONE

    def test_skip_verification(self):
        """ACQUIRING → SEALED is valid when verify is not requested."""
        s = Session()
        s.bind_context("CASE-002", "Examiner", "/tmp")
        s.begin_acquisition()
        s.seal()
        assert s.state == SessionState.SEALED
        s.finalize()
        assert s.state == SessionState.DONE

    def test_illegal_new_to_acquiring(self):
        s = Session()
        with pytest.raises(SessionStateError, match="Illegal transition"):
            s.begin_acquisition()

    def test_illegal_double_bind(self):
        s = Session()
        s.bind_context("C1", "E1", "/tmp")
        with pytest.raises(SessionStateError):
            s.bind_context("C2", "E2", "/tmp")

    def test_illegal_seal_from_new(self):
        s = Session()
        with pytest.raises(SessionStateError):
            s.seal()

    def test_illegal_finalize_from_acquiring(self):
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        with pytest.raises(SessionStateError):
            s.finalize()

    def test_no_transition_after_done(self):
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.seal()
        s.finalize()
        with pytest.raises(SessionStateError, match="NONE"):
            s.begin_acquisition()


# ═══════════════════════════════════════════════════════════════════════
# StreamHasher tests
# ═══════════════════════════════════════════════════════════════════════

class TestStreamHasher:
    def test_empty_hash(self):
        h = StreamHasher()
        assert h.md5_hex == hashlib.md5(b"").hexdigest()
        assert h.sha256_hex == hashlib.sha256(b"").hexdigest()

    def test_known_data(self):
        data = b"forensic evidence stream test data"
        h = StreamHasher()
        h.update(data)
        assert h.md5_hex == hashlib.md5(data).hexdigest()
        assert h.sha256_hex == hashlib.sha256(data).hexdigest()

    def test_incremental_matches_bulk(self):
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        h = StreamHasher()
        for c in chunks:
            h.update(c)

        combined = b"".join(chunks)
        assert h.md5_hex == hashlib.md5(combined).hexdigest()
        assert h.sha256_hex == hashlib.sha256(combined).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
# RawWriter tests
# ═══════════════════════════════════════════════════════════════════════

class TestRawWriter:
    def test_write_and_read_back(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as tmp:
            path = tmp.name

        try:
            w = RawWriter(path)
            w.write(b"hello ")
            w.write(b"world")
            w.close()

            with open(path, "rb") as f:
                assert f.read() == b"hello world"
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════
# Policy / dd command tests
# ═══════════════════════════════════════════════════════════════════════

class TestPolicy:
    def test_dd_command_safe_mode(self):
        cmd = build_dd_command("/dev/sda", 0, safe_mode=True)
        assert "conv=noerror,sync" in cmd
        assert "if=/dev/sda" in cmd
        assert "skip=0" in cmd

    def test_dd_command_no_safe_mode(self):
        cmd = build_dd_command("/dev/sdb", 4096, safe_mode=False)
        assert "conv=" not in cmd
        assert "skip=4096" in cmd

    def test_dd_command_resume_offset(self):
        cmd = build_dd_command("/dev/sda", 1048576, safe_mode=True)
        assert "skip=1048576" in cmd
        assert "iflag=skip_bytes" in cmd
