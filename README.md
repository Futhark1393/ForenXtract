# Remote Forensic Imager (RFI)

![CI](https://github.com/Futhark1393/Remote-Forensic-Imager/actions/workflows/python-ci.yml/badge.svg)

**Author:** Futhark1393  
**Version:** 3.0.0  
**License:** MIT  

Remote Forensic Imager (RFI) is a **case-first remote disk acquisition framework** built with **Python + PyQt6**.

It enforces structured forensic workflows through an **explicit session state machine**, generates a **cryptographically hash-chained audit trail (JSONL)**, supports optional **source-to-stream SHA-256 verification**, and produces **TXT/PDF forensic reports** suitable for evidentiary documentation.

---

## Engineering Documentation

A detailed engineering write-up covering:

- Architecture decisions  
- Audit trail hash-chain model  
- Integrity verification approach  
- Threat considerations  

is available here:

👉 https://kemalsebzeci-site.vercel.app/blog/rfi-architecture

---

## Interface Preview

Screenshots included in `./screenshots/`

- Case Wizard  
  ![Case Wizard](screenshots/case_wizard.png)

- Main UI (Idle)  
  ![Main UI Idle](screenshots/main_ui_idle.png)

- Remote Disk Discovery  
  ![Disk Discovery](screenshots/disk_discovery.png)

- Acquisition Running  
  ![Acquisition Running](screenshots/acquisition_running.png)

- Report Preview  
  ![Report Preview](screenshots/report_preview.png)

---

# Core Capabilities

## Case-First Workflow

- Mandatory Case Wizard at startup
- Case Number + Examiner required
- Evidence directory binding required
- No acquisition allowed without active case context

## Session State Machine

RFI enforces forensic workflow ordering through an explicit state machine:

~~~text
NEW → CONTEXT_BOUND → ACQUIRING → VERIFYING → SEALED → DONE
~~~

- `bind_context()` — NEW → CONTEXT_BOUND (case wizard completion)
- `begin_acquisition()` — CONTEXT_BOUND → ACQUIRING (start imaging)
- `begin_verification()` — ACQUIRING → VERIFYING (post-acq hash check)
- `seal()` — ACQUIRING|VERIFYING → SEALED (lock audit trail)
- `finalize()` — SEALED → DONE

Illegal transitions (e.g., acquiring before context binding, logging after sealing) raise `SessionStateError` and halt operation. The GUI drives the session — it cannot bypass the workflow order.

## Tamper-Evident Audit Logging (JSONL)

- Structured per-session audit trail
- Cryptographic chaining (`prev_hash → entry_hash`)
- Deterministic JSON serialization
- Forced disk flush (`fsync`) per record
- Optional sealing (best-effort):
  - `chmod 444`
  - `chattr +i` (if available)
- Offline chain verification support

## Acquisition & Integrity

- SSH-based acquisition via pure-Python engine (headless-testable, no Qt dependency)
- Remote disk discovery (`lsblk`)
- On-the-fly dual hashing (MD5 + SHA-256) via `StreamHasher`
- Optional post-acquisition remote SHA-256 verification
- Safe Mode (`conv=noerror,sync`)
- Optional write-blocker enforcement (best-effort)
- Automatic retry on connection loss (up to 3 retries with resume)
- Configurable bandwidth throttling

## Reporting

- TXT forensic report
- PDF forensic report
- Includes:
  - Local hash values
  - Optional source hash
  - Verification result
  - Audit trail hash
  - Seal status

---

# CLI Tooling

RFI includes a command-line verifier for audit trails.

## Verify Audit Chain

~~~bash
python rfi_verify.py AuditTrail_CASE_SESSION.jsonl
~~~

Or if installed as alias:

~~~bash
rfi-verify AuditTrail_CASE_SESSION.jsonl
~~~

Exit codes:

- `0` → PASS  
- `2` → FAIL (tampering detected)  
- `1` → Error  

---

# Architecture

~~~text
rfi/
├── ui/                              # Qt / GUI layer
│   ├── gui.py                       # CaseWizard + ForensicApp (Session-driven)
│   ├── workers.py                   # Thin QThread wrapper (~70 lines, no business logic)
│   └── resources/
│       └── forensic_qt6.ui
├── core/                            # Business logic (Qt-free, headless-testable)
│   ├── session.py                   # Workflow state machine (NEW → DONE)
│   ├── hashing.py                   # StreamHasher (MD5 + SHA-256)
│   ├── policy.py                    # Write-blocker enforcement, dd command builder
│   └── acquisition/
│       ├── base.py                  # AcquisitionEngine (pure Python)
│       ├── raw.py                   # RawWriter
│       ├── ewf.py                   # EwfWriter
│       └── verify.py                # Post-acquisition remote hash verification
├── audit/                           # Tamper-evident logging
│   ├── logger.py                    # ForensicLogger (hash-chained JSONL)
│   └── verify.py                    # AuditChainVerifier
├── report/
│   └── report_engine.py             # TXT + PDF forensic reporting
└── deps/
    └── dependency_checker.py        # Runtime dependency validation
~~~

### Design Principles

- **Layered separation** — UI knows nothing about SSH; core knows nothing about Qt
- **Headless-testable engine** — `AcquisitionEngine` uses callbacks, not Qt signals
- **State machine enforcement** — illegal workflow transitions are impossible
- **Fail-secure behavior** — audit failures halt acquisition
- **Tamper-evident logging** — deterministic hash chains with cryptographic sealing
- **Minimal implicit trust** — every component operates with least privilege

### Testing

~~~bash
python -m pytest tests/ -v
~~~

Unit tests cover:
- Session state machine (valid/invalid transitions)
- StreamHasher (incremental hashing correctness)
- RawWriter (write/close behavior)
- Policy helpers (dd command construction)
- AuditChainVerifier (chain integrity validation)

---

# Installation

## 1) Clone

~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
~~~

---

## 2) System Dependencies (Linux)

### Ubuntu / Debian / Kali

~~~bash
sudo apt update
sudo apt install -y \
  libegl1 libgl1 libglib2.0-0 libxkbcommon0 libxkbcommon-x11-0 \
  libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
  libxcb-render0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 \
  libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 libxrender1 libxi6 \
  libsm6 libice6 libfontconfig1 libfreetype6
~~~

### Fedora

~~~bash
sudo dnf install -y qt6-qtbase qt6-qtbase-gui mesa-libEGL mesa-libGL
~~~

---

## 3) Python Dependencies

~~~bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
~~~

Minimal install:

~~~bash
pip install PyQt6 qt-material paramiko fpdf2
~~~

---

## 4) Optional: E01 (EWF) Support

E01 imaging requires **libewf + Python bindings**.

### Debian / Ubuntu / Kali

~~~bash
sudo apt install -y libewf2 python3-libewf
~~~

### Alternative (pip)

~~~bash
pip install libewf-python
~~~

If E01 bindings are not installed:

- RAW acquisition works normally
- E01 option will be unavailable

---

# Running

~~~bash
python main_qt6.py
~~~

Or:

~~~bash
rfi
~~~

---

# Output Artifacts

Inside the selected Evidence Directory:

- `evidence_<CASE>_<UTC>.raw` or `.E01`
- `AuditTrail_<CASE>_<SESSION>.jsonl`
- `AuditConsole_<CASE>.log`
- `Report_<CASE>_<UTC>.pdf`
- `Report_<CASE>_<UTC>.txt`

---

# Notes on Verification

- E01 is a container format.
- Integrity is calculated on the acquisition stream.
- If acquiring from a live system disk, post-acquisition `/dev/...` hashing may differ due to ongoing writes.
- For strict source-to-image equivalence:
  - Use snapshots
  - Use unmounted devices
  - Use hardware write-blockers

This is expected behavior and not a bug.

---

# License

MIT License — see [LICENSE](LICENSE)

---

# Author

Futhark1393
