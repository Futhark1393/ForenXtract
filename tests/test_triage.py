# Tests for ForenXtract (FX) triage modules: NetworkStateCollector, ProcessListCollector,
# MemoryDumpCollector, TriageOrchestrator.
# All tests use mock SSH to avoid needing a real remote host.

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from fx.triage.network import NetworkStateCollector
from fx.triage.processes import ProcessListCollector
from fx.triage.memory import MemoryDumpCollector
from fx.triage.orchestrator import TriageOrchestrator


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _mock_ssh_exec(responses: dict):
    """
    Create a patched ssh_exec that returns canned responses based on
    substring matching in the command string.

    responses: { "keyword_in_cmd": ("stdout", "stderr", exit_code), ... }
    Default: ("", "", 0)
    """
    def _side_effect(ssh, cmd):
        for keyword, result in responses.items():
            if keyword in cmd:
                return result
        return ("", "", 0)
    return _side_effect


# ═══════════════════════════════════════════════════════════════════════
# ProcessListCollector tests
# ═══════════════════════════════════════════════════════════════════════

class TestProcessListCollector:
    def test_parse_ps_output_valid(self):
        """_parse_ps_output should correctly parse ps aux lines."""
        raw = (
            "root         1  0.0  0.1 169356 13240 ?        Ss   09:00   0:02 /sbin/init\n"
            "www-data  1234  1.5  2.3 456789 23456 ?        S    09:01   1:15 /usr/sbin/apache2 -k start\n"
            "user      5678  0.0  0.0  12340  1234 pts/0    R+   09:05   0:00 ps aux\n"
        )
        collector = ProcessListCollector()
        processes = collector._parse_ps_output(raw)

        assert len(processes) == 3
        assert processes[0]["user"] == "root"
        assert processes[0]["pid"] == "1"
        assert processes[0]["command"] == "/sbin/init"
        assert processes[1]["user"] == "www-data"
        assert processes[1]["pid"] == "1234"
        assert "apache2" in processes[1]["command"]

    def test_parse_ps_output_empty(self):
        collector = ProcessListCollector()
        assert collector._parse_ps_output("") == []
        assert collector._parse_ps_output("   \n  \n") == []

    def test_parse_ps_output_short_lines_ignored(self):
        """Lines with fewer than 11 fields should be skipped."""
        raw = "root 1 0.0 0.1\nshort line\n"
        collector = ProcessListCollector()
        assert collector._parse_ps_output(raw) == []

    @patch("fx.triage.processes.ssh_exec")
    def test_collect_saves_artifacts(self, mock_exec):
        """collect() should save TXT and JSON artifacts."""
        ps_output = (
            "root         1  0.0  0.1 169356 13240 ?        Ss   09:00   0:02 /sbin/init\n"
            "user      5678  0.0  0.0  12340  1234 pts/0    R+   09:05   0:00 ps aux\n"
        )
        # First call = ps aux, subsequent calls = hash commands
        mock_exec.side_effect = [
            (ps_output, "", 0),  # ps aux
            ("1:abc123\n5678:def456", "", 0),  # hash executables
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = ProcessListCollector()
            result = collector.collect(MagicMock(), "CASE-T1", tmpdir, hash_exes=True)

            assert result["process_count"] == 2
            assert result.get("txt_path") is not None
            assert result.get("json_path") is not None
            assert os.path.exists(result["txt_path"])
            assert os.path.exists(result["json_path"])

            # Verify JSON is valid
            with open(result["json_path"]) as f:
                data = json.load(f)
            assert data["case_no"] == "CASE-T1"
            assert len(data["processes"]) == 2

    @patch("fx.triage.processes.ssh_exec")
    def test_collect_no_hash(self, mock_exec):
        """collect(hash_exes=False) should skip executable hashing."""
        ps_output = "root 1 0.0 0.1 169356 13240 ? Ss 09:00 0:02 /sbin/init\n"
        mock_exec.return_value = (ps_output, "", 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = ProcessListCollector()
            result = collector.collect(MagicMock(), "CASE-T2", tmpdir, hash_exes=False)
            assert result["process_count"] == 1
            # Only one ssh_exec call (ps aux), no hash call
            assert mock_exec.call_count == 1

    @patch("fx.triage.processes.ssh_exec")
    def test_collect_ssh_error(self, mock_exec):
        """collect() should handle SSH failure gracefully."""
        mock_exec.side_effect = Exception("SSH connection lost")

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = ProcessListCollector()
            result = collector.collect(MagicMock(), "CASE-ERR", tmpdir)
            assert result["process_count"] == 0


# ═══════════════════════════════════════════════════════════════════════
# NetworkStateCollector tests
# ═══════════════════════════════════════════════════════════════════════

class TestNetworkStateCollector:
    @patch("fx.triage.network.ssh_exec")
    def test_collect_all_commands(self, mock_exec):
        """collect() should run all defined commands."""
        mock_exec.return_value = ("mock output", "", 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = NetworkStateCollector()
            result = collector.collect(MagicMock(), "NET-001", tmpdir)

            assert result["case_no"] == "NET-001"
            assert "data" in result
            # All command keys should be present
            for key in NetworkStateCollector.COMMANDS:
                assert key in result["data"]
                assert result["data"][key] == "mock output"

    @patch("fx.triage.network.ssh_exec")
    def test_collect_saves_txt_and_json(self, mock_exec):
        mock_exec.return_value = ("test data", "", 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = NetworkStateCollector()
            result = collector.collect(MagicMock(), "NET-002", tmpdir)

            assert result.get("txt_path") is not None
            assert result.get("json_path") is not None
            assert os.path.exists(result["txt_path"])
            assert os.path.exists(result["json_path"])

            # Verify TXT content
            txt_content = open(result["txt_path"]).read()
            assert "NETWORK STATE" in txt_content
            assert "NET-002" in txt_content

    @patch("fx.triage.network.ssh_exec")
    def test_collect_handles_command_error(self, mock_exec):
        """Individual command failures should not stop collection."""
        def _side_effect(ssh, cmd):
            if "ss " in cmd or "netstat" in cmd:
                raise Exception("command not found")
            return ("ok", "", 0)

        mock_exec.side_effect = _side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = NetworkStateCollector()
            result = collector.collect(MagicMock(), "NET-ERR", tmpdir)
            assert "ERROR" in result["data"]["connections"]
            assert result["data"]["routes"] == "ok"

    @patch("fx.triage.network.ssh_exec")
    def test_collect_empty_output(self, mock_exec):
        """Empty command output should be handled gracefully."""
        mock_exec.return_value = ("", "some warning", 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = NetworkStateCollector()
            result = collector.collect(MagicMock(), "NET-EMPTY", tmpdir)
            # Empty stdout should include stderr info
            for key in result["data"]:
                assert "stderr" in result["data"][key].lower() or result["data"][key]


# ═══════════════════════════════════════════════════════════════════════
# MemoryDumpCollector tests
# ═══════════════════════════════════════════════════════════════════════

class TestMemoryDumpCollector:
    @patch("fx.triage.memory.ssh_exec")
    def test_collect_meminfo(self, mock_exec):
        """_collect_meminfo should parse /proc/meminfo output."""
        meminfo_out = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         8192000 kB\n"
            "MemAvailable:   12000000 kB\n"
        )
        mock_exec.return_value = (meminfo_out, "", 0)

        collector = MemoryDumpCollector()
        result = collector._collect_meminfo(MagicMock())
        assert result["source"] == "/proc/meminfo"
        assert "MemTotal" in result["data"]
        assert "16384000 kB" in result["data"]["MemTotal"]

    @patch("fx.triage.memory.ssh_exec")
    def test_collect_kallsyms(self, mock_exec):
        mock_exec.return_value = ("95000 /proc/kallsyms", "", 0)

        collector = MemoryDumpCollector()
        result = collector._collect_kallsyms_summary(MagicMock())
        assert result["symbol_count"] == "95000"

    @patch("fx.triage.memory.ssh_exec")
    def test_collect_modules(self, mock_exec):
        modules_out = (
            "ext4 745472 1 - Live 0xffffffffc0300000\n"
            "mbcache 16384 1 ext4, Live 0xffffffffc02f0000\n"
        )
        mock_exec.return_value = (modules_out, "", 0)

        collector = MemoryDumpCollector()
        modules = collector._collect_modules(MagicMock())
        assert len(modules) == 2
        assert modules[0]["name"] == "ext4"
        assert modules[0]["size"] == "745472"

    @patch("fx.triage.memory.ssh_exec")
    def test_check_lime_device_none(self, mock_exec):
        mock_exec.return_value = ("NONE", "", 0)

        collector = MemoryDumpCollector()
        result = collector._check_lime_device(MagicMock())
        assert result["lime_device"] is None

    @patch("fx.triage.memory.ssh_exec")
    def test_check_lime_device_found(self, mock_exec):
        mock_exec.return_value = ("/dev/lime0", "", 0)

        collector = MemoryDumpCollector()
        result = collector._check_lime_device(MagicMock())
        assert result["lime_device"] == "/dev/lime0"

    @patch("fx.triage.memory.ssh_exec")
    def test_collect_metadata_only(self, mock_exec):
        """collect() with attempt_kcore=False should only gather metadata."""
        def _side_effect(ssh, cmd):
            if "meminfo" in cmd:
                return ("MemTotal: 8192 kB\n", "", 0)
            if "kallsyms" in cmd:
                return ("50000 /proc/kallsyms", "", 0)
            if "modules" in cmd:
                return ("ext4 745472 1 - Live 0x0\n", "", 0)
            if "lime" in cmd:
                return ("NONE", "", 0)
            return ("", "", 0)

        mock_exec.side_effect = _side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MemoryDumpCollector()
            result = collector.collect(MagicMock(), "MEM-001", tmpdir, attempt_kcore=False)
            assert result["kcore"]["status"] == "SKIPPED"
            assert result["meminfo"]["source"] == "/proc/meminfo"
            assert result.get("json_path") is not None

    @patch("fx.triage.memory.ssh_exec")
    def test_collect_saves_json(self, mock_exec):
        mock_exec.return_value = ("NONE", "", 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MemoryDumpCollector()
            result = collector.collect(MagicMock(), "MEM-JSON", tmpdir, attempt_kcore=False)
            assert result.get("json_path") is not None
            assert os.path.exists(result["json_path"])

            with open(result["json_path"]) as f:
                data = json.load(f)
            assert data["case_no"] == "MEM-JSON"


# ═══════════════════════════════════════════════════════════════════════
# TriageOrchestrator tests
# ═══════════════════════════════════════════════════════════════════════

class TestTriageOrchestrator:
    @patch("fx.triage.orchestrator.MemoryDumpCollector")
    @patch("fx.triage.orchestrator.ProcessListCollector")
    @patch("fx.triage.orchestrator.NetworkStateCollector")
    def test_run_all_collectors(self, MockNet, MockProc, MockMem):
        """When all collectors are enabled, all should be called."""
        MockNet.return_value.collect.return_value = {
            "json_path": None, "txt_path": None, "data": {}
        }
        MockProc.return_value.collect.return_value = {
            "json_path": None, "txt_path": None, "process_count": 5
        }
        MockMem.return_value.collect.return_value = {
            "json_path": None, "kcore": {"status": "SKIPPED"}, "lime_device": {"lime_device": None}
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=True, run_processes=True, run_memory=True
            )
            result = orch.run(MagicMock(), "ORCH-001", tmpdir)

            assert "collectors" in result
            assert "network" in result["collectors"]
            assert "processes" in result["collectors"]
            assert "memory" in result["collectors"]
            assert result["collectors"]["network"]["status"] == "OK"
            assert result["collectors"]["processes"]["status"] == "OK"
            assert result["collectors"]["memory"]["status"] == "OK"

    @patch("fx.triage.orchestrator.NetworkStateCollector")
    def test_run_network_only(self, MockNet):
        MockNet.return_value.collect.return_value = {
            "json_path": None, "txt_path": None, "data": {}
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=True, run_processes=False, run_memory=False
            )
            result = orch.run(MagicMock(), "ORCH-NET", tmpdir)

            assert "network" in result["collectors"]
            assert "processes" not in result["collectors"]
            assert "memory" not in result["collectors"]

    @patch("fx.triage.orchestrator.ProcessListCollector")
    @patch("fx.triage.orchestrator.NetworkStateCollector")
    def test_collector_error_does_not_halt(self, MockNet, MockProc):
        """A failing collector should not prevent others from running."""
        MockNet.return_value.collect.side_effect = Exception("network error")
        MockProc.return_value.collect.return_value = {
            "json_path": None, "txt_path": None, "process_count": 3
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=True, run_processes=True, run_memory=False
            )
            result = orch.run(MagicMock(), "ORCH-ERR", tmpdir)

            assert result["collectors"]["network"]["status"] == "ERROR"
            assert result["collectors"]["processes"]["status"] == "OK"

    def test_creates_triage_directories(self):
        """Orchestrator should create triage/data and triage/summaries dirs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=False, run_processes=False, run_memory=False
            )
            result = orch.run(MagicMock(), "ORCH-DIRS", tmpdir)

            assert os.path.isdir(os.path.join(tmpdir, "triage"))
            assert os.path.isdir(os.path.join(tmpdir, "triage", "data"))
            assert os.path.isdir(os.path.join(tmpdir, "triage", "summaries"))

    def test_status_callback(self):
        """on_status callback should be called during orchestration."""
        statuses = []
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=False, run_processes=False, run_memory=False,
                on_status=lambda msg: statuses.append(msg)
            )
            orch.run(MagicMock(), "ORCH-CB", tmpdir)
            assert any("Complete" in s for s in statuses)

    def test_summary_has_timestamp_and_case(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = TriageOrchestrator(
                run_network=False, run_processes=False, run_memory=False
            )
            result = orch.run(MagicMock(), "ORCH-META", tmpdir)
            assert result["case_no"] == "ORCH-META"
            assert "triage_timestamp_utc" in result
