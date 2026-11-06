# QKD-SDWAN PoC: Distributed P2P SD-WAN dengan Simulasi QKD BB84, Machine Learning, Auto-Enrollment Join Token, dan Transfer Data P2P

Proof-of-Concept (PoC) sistem **SD-WAN Terdistribusi Lintas Platform (Linux & Windows)** yang mengintegrasikan:
- **Protokol Distribusi Kunci Kuantum (QKD) BB84 Berbasis Soket** langsung antar *endpoint* (Peer-to-Peer) dengan simulasi atenuasi serat optik, depolarisasi kanal, penyadapan *intercept-resend* (Eve), koreksi kesalahan paritas blok **Cascade 2-Pass**, dan *privacy amplification* **HKDF-SHA256**.
- **Manajemen Tunnel Overlay P2P WireGuard** yang menggabungkan pertukaran kunci X25519 dengan penyuntikan kunci simetris 256-bit hasil BB84 ke slot `PresharedKey` (PSK) secara berkala tanpa melewatkan trafik data maupun kunci rahasia ke Central Controller.
- **Pendaftaran Otomatis Berbasis Join Token (*Token-based Auto-Enrollment*)**: Pendaftaran node endpoint zero-touch yang mengalokasikan IP overlay unik dan mendistribusikan kredensial klaster secara otomatis.
- **Transfer Data & File P2P Terenkripsi dengan Verifikasi Integritas SHA-256**: Pengiriman dan penerimaan pesan teks maupun payload file terenkripsi AEAD (`ChaCha20Poly1305` dengan PSK BB84 256-bit) antar Client via jalur `DIRECT_P2P` atau `RELAY_P2P` dengan auto-retry UDP, deduplikasi paket, dan verifikasi SHA-256 end-to-end.
- **Dual Interactive CLI Dashboards (Controller & Client)**: Tampilan dashboard terminal ASCII 4-panel interaktif baik pada **Central Controller** (`qkd-sdwan-controller dashboard`) maupun pada **Endpoint Client** (`qkd-sdwan-client dashboard`).
- **Installer Portabel Lintas Platform**: Paket aplikasi portabel `.pyz` dan installer interaktif/non-interaktif untuk **Linux** (`.sh`) dan **Windows** (`.ps1` & `.bat`).

Dokumen arsitektur teknis lengkap tersedia pada [`docs/ARCHITECTURE_BLUEPRINT.md`](docs/ARCHITECTURE_BLUEPRINT.md).

---

## Struktur Repositori

```text
.
├── dist/                                # Artefak installer & paket distribusi portabel (dihasilkan oleh build_installers.py)
│   ├── MANIFEST.json                    # Manifest artefak distribusi, ukuran byte, dan checksum SHA-256
│   ├── install-client-linux.sh          # Installer Linux Endpoint Client
│   ├── install-client-windows.bat       # Wrapper Batch Windows Endpoint Client
│   ├── install-client-windows.ps1       # Installer PowerShell Windows Endpoint Client
│   ├── install-controller-linux.sh      # Installer Linux Central Controller
│   ├── install-controller-windows.bat   # Wrapper Batch Windows Central Controller
│   ├── install-controller-windows.ps1   # Installer PowerShell Windows Central Controller
│   ├── qkd-sdwan-client.pyz             # Paket portabel zipapp Endpoint Client
│   └── qkd-sdwan-controller.pyz         # Paket portabel zipapp Central Controller
├── docs/
│   └── ARCHITECTURE_BLUEPRINT.md        # Blueprint arsitektur, spesifikasi protokol, formulasi ML & roadmap
├── qkd_sdwan/
│   ├── __init__.py
│   ├── common/
│   │   ├── __init__.py
│   │   └── models.py                    # Model data (EnrollmentToken, P2PDataMessage, LinkTelemetry, RouteDirective, BB84SessionResult)
│   ├── client/
│   │   ├── __init__.py
│   │   ├── agent.py                     # Agen endpoint SD-WAN, enrollment token, transfer P2P, dan Client CLI
│   │   ├── bb84_engine.py               # Simulator kanal kuantum & negosiasi TCP BB84 terautentikasi HMAC-SHA256
│   │   └── wg_manager.py                # Daemon tunnel P2P WireGuard, inbox pesan, dan injeksi 256-bit PSK
│   └── controller/
│       ├── __init__.py
│       ├── cli.py                       # CLI Central Controller, manajemen token, dan ASCII CLI Dashboard
│       ├── ml_engine.py                 # Isolation Forest 6D Anomaly Detector & Dynamic Graph Route Optimizer
│       └── server.py                    # REST API Server Central Controller, Join Token, dan alokasi IP overlay
├── scripts/
│   ├── build_installers.py              # Generator paket distribusi .pyz, installer shell/PowerShell, dan MANIFEST.json
│   ├── install_client.ps1               # Source installer PowerShell Client (Windows)
│   ├── install_client.sh                # Source installer shell Client (Linux)
│   ├── install_controller.ps1           # Source installer PowerShell Controller (Windows)
│   ├── install_controller.sh            # Source installer shell Controller (Linux)
│   └── run_poc_demo.py                  # Demo end-to-end simulasi pendaftaran token, 4 skenario QKD/ML, transfer data P2P, & dashboard
└── tests/
    └── test_qkd_sdwan.py                # Suite pengujian unit & integrasi otomatis (unittest)
```

---

## Prasyarat Sistem

- **Python**: 3.11+ (kompatibel penuh hingga Python 3.14)
- **Pustaka Python**: Pustaka standar Python + `cryptography` (untuk primitif `X25519`, `HKDF-SHA256`, dan `ChaCha20Poly1305`)
- **Sistem Operasi**:
  - **Linux**: Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+, Arch Linux
  - **Windows**: Windows 10/11, Windows Server 2019/2022 (PowerShell 5.1+ atau PowerShell 7+)
- **WireGuard Tools (Opsional)**: Jika `/usr/bin/wg` tersedia dan dijalankan sebagai `root` (`--prefer-kernel-wg`), daemon mengeksekusi `wg set <iface> peer <pubkey> preshared-key /dev/stdin` secara langsung. Pada lingkungan non-root atau tanpa `wireguard-tools`, daemon otomatis menjalankan backend `USERSPACE_CRYPTO_WG` berbasis UDP + `X25519` + `BB84-PSK` + `ChaCha20-Poly1305`.

---

## Panduan Cepat

### 0. Clone dari GitHub & One-Command Install (Core Controller maupun Client)

Repositori ini sudah menyertakan paket portabel `.pyz` dan skrip installer lintas platform siap pakai di dalam direktori `dist/`, sehingga Anda cukup melakukan `git clone` (atau `git pull`) dan langsung menjalankan installer:

```bash
git clone https://github.com/fhanyuh/qkd-sdwan.git
cd qkd-sdwan
pip install -r requirements.txt
```

- **Install Core (Central Controller)**:
  - **Linux**:
    ```bash
    bash dist/install-controller-linux.sh
    ```
  - **Windows (PowerShell)**:
    ```powershell
    .\dist\install-controller-windows.ps1
    ```
- **Install Endpoint Client**:
  - **Linux**:
    ```bash
    bash dist/install-client-linux.sh
    ```
  - **Windows (PowerShell)**:
    ```powershell
    .\dist\install-client-windows.ps1
    ```
- **Atau Install Langsung via `pip` (Memasang CLI `qkd-sdwan-controller` & `qkd-sdwan-client` sekaligus)**:
  ```bash
  pip install .
  ```

---

### 1. Membangun Paket Distribusi Portabel (`scripts/build_installers.py`)

Perintah ini memaketkan kode sumber menjadi aplikasi portabel `.pyz` dan menyalin installer Linux & Windows ke direktori `dist/`:

```bash
python3 scripts/build_installers.py
```

Artefak yang dihasilkan pada `dist/`:
- `qkd-sdwan-controller.pyz` & `qkd-sdwan-client.pyz`
- `install-controller-linux.sh` & `install-client-linux.sh`
- `install-controller-windows.ps1` & `install-controller-windows.bat`
- `install-client-windows.ps1` & `install-client-windows.bat`
- `MANIFEST.json` (memuat ukuran byte dan checksum SHA-256 setiap file)

---

### 2. Menjalankan Simulasi End-to-End (`scripts/run_poc_demo.py`)

Skrip demo menjalankan alur lengkap secara otomatis:
1. Inisialisasi Central Controller dan pembuatan Join Token pendaftaran.
2. Pendaftaran otomatis (*Auto-Enrollment*) 3 endpoint (`edge-jkt-01`, `edge-bdg-02`, `edge-sby-03`) dengan alokasi IP overlay (`10.200.0.10`, `10.200.0.11`, `10.200.0.12`).
3. Eksekusi 4 skenario jaringan dan serangan kuantum (Normal, Degradasi Underlay, Penyadapan Moderat $\eta_{\text{eve}} = 0.30$, dan Penyadapan Agresif $\eta_{\text{eve}} = 0.65$ / Abort).
4. Transfer data teks dan file biner terenkripsi P2P (`DIRECT_P2P` dan `RELAY_P2P`).
5. Render penuh **4-Panel Interactive ASCII CLI Dashboard** baik pada **Endpoint Client** maupun **Central Controller**.

```bash
python3 scripts/run_poc_demo.py
```

---

### 3. Menjalankan Suite Pengujian Otomatis (`unittest`)

Seluruh 11 modul pengujian unit, integrasi, & reliabilitas dapat dijalankan dengan:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Cakupan pengujian mencakup:
- `test_bb84_normal_key_agreement`: Derivasi kunci BB84 identik 32-byte pada Alice dan Bob.
- `test_bb84_eavesdrop_abort`: Pembatalan kuantum saat QBER > 11% akibat penyadapan Eve.
- `test_bb84_hmac_authentication_rejects_tampering`: Penolakan manipulasi frame kuantum klasik.
- `test_wg_psk_injection_and_encrypted_p2p_dataplane`: Pengujian injeksi PSK 256-bit dan enkripsi ChaCha20Poly1305.
- `test_ml_anomaly_and_route_optimization`: Transisi rute `DIRECT_P2P` -> `RELAY_P2P` oleh Isolation Forest.
- `test_full_distributed_sdwan_controller_and_agents`: Integrasi 1 Controller + 3 Agent melintasi 4 skenario.
- `test_token_enrollment_and_ip_allocation`: Siklus hidup Join Token, alokasi IP overlay, dan batas pemakaian/pencabutan token.
- `test_p2p_client_data_and_file_transfer`: Pengiriman teks & file biner P2P terenkripsi via rute langsung dan relay.
- `test_controller_cli_dashboard_and_cross_platform_installers`: Output ASCII Dashboard Controller dan builder paket installer lintas platform.
- `test_client_cli_dashboard_and_file_integrity`: Output 4-panel ASCII Dashboard Client, ekspor file inbox ke disk, dan deteksi integritas SHA-256.
- `test_concurrent_bb84_and_out_of_order_enrollment_reliability`: Reliabilitas negosiasi BB84 paralel multi-thread dan auto-sync topologi pada pendaftaran *out-of-order*.

## Pemasangan & Penggunaan Lintas Platform

### A. Central Controller

#### Pemasangan di Linux
Jalankan installer interaktif:
```bash
# Mode interaktif (Wizard tanya-jawab)
bash dist/install-controller-linux.sh

# Atau mode unattended (otomasi/CI)
bash dist/install-controller-linux.sh --non-interactive \
  --prefix /opt/qkd-sdwan-controller \
  --host 0.0.0.0 \
  --port 8080 \
  --subnet-prefix 10.200.0. \
  --bootstrap-token qkd-join-cluster-token-2025
```

#### Pemasangan di Windows
Buka PowerShell atau CMD sebagai Administrator:
```powershell
# Mode interaktif di PowerShell
.\dist\install-controller-windows.ps1

# Atau via Batch launcher
dist\install-controller-windows.bat -NonInteractive -BindHost "0.0.0.0" -Port 8080
```

#### Menjalankan Central Controller & CLI Dashboard
```bash
# Menjalankan server Controller dengan konsol dashboard interaktif
qkd-sdwan-controller serve --dashboard

# Menampilkan snapshot dashboard satu kali
qkd-sdwan-controller dashboard --once

# Menampilkan dashboard live auto-refresh setiap 2 detik
qkd-sdwan-controller dashboard --interval 2.0

# Manajemen Join Token
qkd-sdwan-controller token list
qkd-sdwan-controller token create --label "branch-bali" --max-uses 5 --ttl 86400
qkd-sdwan-controller token revoke --token-id tok-xxxx
```

---

### B. Endpoint Client

#### Pemasangan di Linux
```bash
# Mode interaktif
bash dist/install-client-linux.sh

# Mode unattended dengan auto-enrollment menggunakan Join Token
bash dist/install-client-linux.sh --non-interactive \
  --prefix /etc/qkd-sdwan \
  --controller-url http://127.0.0.1:8080 \
  --join-token qkd-join-cluster-token-2025 \
  --node-id edge-jkt-01
```

#### Pemasangan di Windows
```powershell
.\dist\install-client-windows.ps1 -NonInteractive `
  -ControllerUrl "http://127.0.0.1:8080" `
  -JoinToken "qkd-join-cluster-token-2025" `
  -NodeId "edge-jkt-01"
```

#### Menggunakan Client CLI
```bash
# 1. Pendaftaran mandiri dengan Join Token
qkd-sdwan-client enroll \
  --controller-url http://127.0.0.1:8080 \
  --join-token <TOKEN_SECRET> \
  --node-id edge-bdg-02 \
  --output-config /etc/qkd-sdwan/endpoint.json

# 2. Mengirim pesan teks terenkripsi P2P ke node lain
qkd-sdwan-client send --to edge-bdg-02 --text "Pesan rahasia ber-PSK BB84 256-bit"

# 3. Mengirim file dokumen/biner terenkripsi P2P ke node lain
qkd-sdwan-client send --to edge-bdg-02 --file /path/to/dokumen.pdf

# 4. Membuka 4-Panel Interactive CLI Dashboard Client (Mode Interaktif / Snapshot / Auto-Refresh)
qkd-sdwan-client dashboard
qkd-sdwan-client dashboard --once
qkd-sdwan-client dashboard --interval 2.0

# 5. Membuka Konsol Interaktif Client (Live Inbox & BB84 Rekeying)
qkd-sdwan-client console
# Perintah di dalam console:
# edge-jkt-01> dashboard                (Tampilkan 4-panel Client CLI Dashboard penuh)
# edge-jkt-01> peers                    (Lihat daftar peer P2P & mode rute)
# edge-jkt-01> rekey edge-bdg-02        (Jalankan negosiasi kunci kuantum BB84 baru)
# edge-jkt-01> send edge-bdg-02 <msg>   (Kirim pesan teks terenkripsi P2P)
# edge-jkt-01> sendfile edge-bdg-02 <f> (Kirim file biner terenkripsi P2P)
# edge-jkt-01> inbox                    (Lihat daftar pesan & file yang diterima)
# edge-jkt-01> savefile 1 ./downloads   (Simpan file dari inbox ke direktori lokal)
# edge-jkt-01> quit

# 6. Memeriksa status identitas endpoint lokal
qkd-sdwan-client status --json
```
---

## Tampilan CLI Dashboard Central Controller

Contoh tampilan **4-Panel Interactive ASCII Dashboard**:

```text
====================================================================================================================
 QKD-SDWAN CENTRAL CONTROLLER — INTERACTIVE CLI DASHBOARD (BB84 QKD + ISOLATION FOREST ML) 
====================================================================================================================
 Controller URL : http://127.0.0.1:8080              | Timestamp          : 2026-11-06 21:11:05 UTC
 Overlay Subnet : 10.200.0.0/24                      | Registered Nodes   : 3
 Active Links   : 3                                  | Routing Directives : 6
--------------------------------------------------------------------------------------------------------------------
[1] CLUSTER ENROLLMENT JOIN TOKENS (Token-Based Zero-Touch Client Onboarding)
+--------------+-------------------+-------+---------+--------+------------------------------------+
| Token ID     | Label             | Uses  | TTL Rem | Status | Join Token (for Client Enrollment) |
+--------------+-------------------+-------+---------+--------+------------------------------------+
| tok-1ea5e17b | bootstrap-default | 3/100 | 86399s  | ACTIVE | qkd-join-5790e279fc901544249a851a  |
+--------------+-------------------+-------+---------+--------+------------------------------------+

[2] REGISTERED P2P SD-WAN ENDPOINT CLIENTS
+-------------+-------------+----------------------+----------+-----------------------+-------------------------+
| Node ID     | Overlay IP  | Underlay WG Endpoint | QKD Port | Auth Token ID         | WG X25519 Public Key    |
+-------------+-------------+----------------------+----------+-----------------------+-------------------------+
| edge-bdg-02 | 10.200.0.11 | 127.0.0.1:42381      | 43363    | enrolled-tok-1ea5e17b | fOPD5JhphXfMvXuisK/v... |
| edge-jkt-01 | 10.200.0.10 | 127.0.0.1:37272      | 39391    | enrolled-tok-1ea5e17b | 0Wl+HNO1WS+TuvE6d/ho... |
| edge-sby-03 | 10.200.0.12 | 127.0.0.1:51963      | 41369    | enrolled-tok-1ea5e17b | fRe9agwFfZSVvfYXYL71... |
+-------------+-------------+----------------------+----------+-----------------------+-------------------------+

[3] QUANTUM BB84 CHANNEL TELEMETRY & ISOLATION FOREST ANOMALY MONITOR
+----------------------------+--------+------------+----------------+---------------+-----------+--------+----------+---------------------+
| Directed Link              | QBER   | Delta QBER | Key Rate (bps) | RTT / Loss    | PSK Epoch | Aborts | ML Score | LinkStatus          |
+----------------------------+--------+------------+----------------+---------------+-----------+--------+----------+---------------------+
| edge-bdg-02 -> edge-sby-03 | 1.34%  | +0.00%     | 7068           | 11.2ms / 0.1% | 1         | 0      | 0.411    | HEALTHY             |
| edge-jkt-01 -> edge-bdg-02 | 2.01%  | +0.00%     | 6774           | 9.5ms / 0.1%  | 1         | 0      | 0.400    | HEALTHY             |
| edge-jkt-01 -> edge-sby-03 | 18.00% | +10.05%    | 0              | 16.0ms / 0.2% | 3         | 1      | 0.882    | COMPROMISED_BLOCKED |
+----------------------------+--------+------------+----------------+---------------+-----------+--------+----------+---------------------+

[4] ACTIVE P2P OVERLAY ROUTING DIRECTIVES (DIRECT_P2P vs RELAY_P2P)
+----------------------------+------------+-------------+-------------------+-------------+--------------------------------------------------+
| Source -> Target           | RouteMode  | Next Hop    | Next Hop Endpoint | Force Rekey | Reason                                           |
+----------------------------+------------+-------------+-------------------+-------------+--------------------------------------------------+
| edge-bdg-02 -> edge-sby-03 | DIRECT_P2P | edge-sby-03 | 127.0.0.1:51963   | NO          | Direct P2P link healthy (cost=14.3)              |
| edge-jkt-01 -> edge-bdg-02 | DIRECT_P2P | edge-bdg-02 | 127.0.0.1:42381   | NO          | Direct P2P link healthy (cost=12.4)              |
| edge-jkt-01 -> edge-sby-03 | RELAY_P2P  | edge-bdg-02 | 127.0.0.1:42381   | YES         | Rerouted via P2P relay edge-bdg-02 due to COM... |
+----------------------------+------------+-------------+-------------------+-------------+--------------------------------------------------+
====================================================================================================================
```
