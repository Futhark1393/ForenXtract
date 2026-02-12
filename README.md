# 🕵️‍♂️ Remote Forensic Imager

**Remote Forensic Imager** is a specialized digital forensics tool designed to acquire full disk images from remote cloud servers (AWS EC2, VPS, etc.) securely and efficiently.

Developed with **Python** and **PyQt6**, this tool allows forensic examiners to perform live data acquisition over an encrypted SSH tunnel without modifying the evidence on the target system.

![GUI Preview](screenshots/gui_preview.png)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Linux-green.svg)

## 🚀 Key Features

* **GUI Based:** User-friendly interface powered by PyQt6.
* **Secure Acquisition:** Uses `SSH` tunneling for end-to-end encrypted data transfer.
* **Live Imaging:** Captures volatile data using `dd` with on-the-fly `gzip` compression to optimize network bandwidth.
* **Safe Mode:** Implements `conv=noerror,sync` to handle bad sectors without stopping the acquisition process.
* **Zip Bomb Analysis:** Includes a post-acquisition analysis thread to detect potential "Zip Bomb" anomalies in the acquired image.
* **Hacker-Style Logging:** Real-time, terminal-style operation logs.

## 🛠️ Requirements

* **Operating System:** Linux (Fedora, Ubuntu, Kali, etc.) - *Recommended for native SSH tools.*
* **Python:** Version 3.x
* **Dependencies:** PyQt6

## 📦 Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
    cd Remote-Forensic-Imager
    ```

2.  **Install Dependencies**
    ```bash
    pip install PyQt6
    ```

## 📖 Usage

1.  **Launch the Application**
    ```bash
    python3 main.py
    ```

2.  **Configure Parameters**
    * **Server IP:** The public IP address of the target machine (e.g., AWS EC2 IP).
    * **User:** The SSH username (e.g., `ubuntu`, `ec2-user`, `root`).
    * **SSH Key:** Select your `.pem` private key file.
    * **Disk:** The target disk identifier (e.g., `/dev/nvme0n1` for AWS Nitro instances or `/dev/xvda`).

3.  **Start Acquisition**
    * Click **"Start Acquisition & Analyze"**.
    * The tool will establish a connection, stream the disk image to your local machine, and save it as `evidence_YYYYMMDD_HHMMSS.img.gz`.

## 🛡️ Forensic Methodology & Verification

This tool adheres to the **RFC 3227** guidelines for evidence collection:
1.  **Minimization:** Minimal footprint on the target system (uses standard system binaries: `dd`, `gzip`).
2.  **Integrity:** Data is transferred via a secure channel.
3.  **Verification:** Automatically suggests hashing the output file post-acquisition.

![Verification Proof](screenshots/terminal_proof.png)
*Figure: SHA-256 Hashing, Write-Blocking, and Content Verification.*

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized forensic investigations** only. The author (Futhark) is not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before accessing remote systems.

---

**Developed by Futhark**
