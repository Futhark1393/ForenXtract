# 🕵️‍♂️ Remote Forensic Imager

**Remote Forensic Imager** is a Python-based digital forensic tool developed to perform live disk and volatile memory (RAM) acquisition from remote servers (AWS EC2, VPS, etc.) over encrypted channels.

Designed for incident responders and forensic examiners, the tool automates the process of collecting bit-stream images while maintaining a strict **Chain of Custody (CoC)**, ensuring data integrity, and adhering to the **"Do No Harm"** forensic principle through optional write-blocking and network throttling.

![GUI Preview](screenshots/gui_preview.png)

## 🚀 Technical Capabilities

* **Live Triage (Fast Recon) (New):** Executes rapid volatile data collection (active network connections, running processes, logged-in users, and kernel logs) before starting the main disk acquisition.
* **Bandwidth Throttling:** Integrates with `pv` (Pipe Viewer) to limit network bandwidth usage (MB/s) during acquisition, preventing production server bottlenecks.
* **Interactive Tooltips (Help):** Embedded forensic guidance for examiners on hover for all UI elements.
* **Live RAM (Memory) Acquisition:** Capable of extracting volatile memory directly from `/proc/kcore`. Bypasses physical write-blockers safely.
* **Software Write Blocker:** Capable of toggling the remote block device to **Read-Only (RO)** mode at the kernel level (`blockdev --setro`).
* **Live Bad Sector Logging:** Monitors `dd` output in real-time to detect and log **I/O errors (Bad Sectors)**.
* **Secure Remote Acquisition:** Establishes encrypted SSH tunnels for secure data transfer.
* **Automated Chain of Custody:** Generates a forensic report (`.txt`) immediately after acquisition.
* **Integrity Verification:** Calculates SHA-256 hash values (Digital Seal) automatically.

---

## 🧪 Laboratory Setup & Testing

### 1. Target Preparation (Remote Side)
Connect to your remote instance and place a "secret" evidence file:

````bash
# Connect to your test server
ssh -i your-key.pem ubuntu@remote-ip

# Inject evidence data
echo "CONFIDENTIAL_DATA_FOUND_BY_FUTHARK1393" > evidence_file.txt
````

### 2. Evidence Collection (Local Side)
1. Run the application: `python3 main_qt6.py`
2. Enter the **Case Number** and **Examiner Name**.
3. Input the Target IP and Disk Path.
4. **(Optional)** Check **"Run Live Triage"** to collect fast volatile system data.
5. **(Optional)** Check **"Limit Bandwidth"** and set a limit (e.g., `10` MB/s) to protect network stability.
6. **(Optional)** Check **"Enable Software Write Blocker"** for kernel-level protection on physical disks.
7. Click **"Take Image and Analyze"** to start the transfer.

### 3. Forensic Validation
````bash
# 1. Lock the evidence (Local Write-Blocking)
chmod 444 evidence_*.img.gz

# 2. Verify Digital Seal (Hash Check)
sha256sum evidence_*.img.gz

# 3. Keyword Search (Content Analysis)
zgrep -a "CONFIDENTIAL_DATA" evidence_*.img.gz
````

---

## 🛡️ Automated Documentation & Crash-Proof Logging

The system generates an official **Forensic Acquisition Report** for every session. Additionally, it maintains a real-time `live_forensic.log` file to preserve operation logs even in case of a system crash.

![Automated Report](screenshots/automated_report.png)

---

## 🛠️ Environment & Installation

* **Development OS:** Fedora 43 Workstation (KDE Plasma)
* **Language:** Python 3.10+
* **Dependencies:** `PyQt6`, `pv` (Pipe Viewer)

````bash
# 1. Install system dependency for bandwidth throttling (Fedora)
sudo dnf install pv

# 2. Clone and Run
git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
cd Remote-Forensic-Imager
pip install PyQt6
python3 main_qt6.py
````

## ⚠️ Disclaimer

This tool includes features that interact with the remote kernel (`blockdev` and `/proc/kcore`). While it implements safety mechanisms, it is intended for **authorized forensic investigations** only. The developer (**Futhark1393**) assumes no liability for unauthorized access or misuse.

---

**Developed by Futhark1393**
