# QKD-SDWAN PoC: Distributed P2P SD-WAN dengan Simulasi QKD BB84, Machine Learning, Auto-Enrollment Join Token, dan Transfer Data P2P

Proof-of-Concept (PoC) sistem **SD-WAN Terdistribusi Lintas Platform (Linux & Windows)** yang mengintegrasikan:
- **Protokol Distribusi Kunci Kuantum (QKD) BB84 Berbasis Soket** langsung antar *endpoint* (Peer-to-Peer) dengan simulasi atenuasi serat optik, depolarisasi kanal, penyadapan *intercept-resend* (Eve), koreksi kesalahan paritas blok **Cascade 2-Pass**, dan *privacy amplification* **HKDF-SHA256**.
- **Manajemen Tunnel Overlay P2P WireGuard** yang menggabungkan pertukaran kunci X25519 dengan penyuntikan kunci simetris 256-bit hasil BB84 ke slot `PresharedKey` (PSK) secara berkala tanpa melewatkan trafik data maupun kunci rahasia ke Central Controller.
- **Pendaftaran Otomatis Zero-Touch (`join_token="auto"`) & Multi-Network WAN/NAT Traversal**: Alokasi IP overlay anti-kolisi otomatis, deteksi *same-NAT LAN hairpinning* vs *cross-NAT WAN*, dan *failover* otomatis via Cloud Relay (`RELAY_P2P`).
- **Real-Time Node Liveness (`ONLINE`/`OFFLINE`) & Zero-Dummy Multi-Probe Telemetry**: Pelacakan keaktifan node secara *real-time* (TTL *heartbeat* 6 detik + notifikasi *graceful disconnect* instan `/api/v1/nodes/disconnect` saat `qkd stop`), pengukuran **RTT, Jitter, Packet Loss, dan Throughput** murni dari multi-probe paket UDP terenkripsi setiap 2 detik + rotasi BB84 otomatis setiap 10 detik tanpa konstanta *dummy*, serta transisi otomatis ke `OFFLINE_DOWN` (`QBER: N/A (OFFLINE)`, `Key Rate: 0 bps`, `Loss: 100.0%`, `RouteMode: QUARANTINED`) saat service peer berhenti.
- **Transfer Data & File P2P Terenkripsi dengan Verifikasi Integritas SHA-256**: Pengiriman dan penerimaan pesan teks maupun payload file terenkripsi AEAD (`ChaCha20Poly1305` dengan PSK BB84 256-bit) antar Client via jalur `DIRECT_P2P` atau `RELAY_P2P` dengan auto-retry UDP, deduplikasi paket, dan verifikasi SHA-256 end-to-end.
- **Global Ergonomic CLI (`qkd` & `qkd-ctl`) dan Dual Interactive 4-Panel CLI Dashboards**: Perintah ringkas global (`qkd up`, `qkd dashboard`, `qkd peers`, `qkd rekey`, `qkd send`, `qkd sendfile`, `qkd inbox`, `qkd stop`) dan dashboard terminal ASCII 4-panel detail pada **Central Controller** maupun **Endpoint Client**.
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

Seluruh 15 modul pengujian unit, integrasi, liveness real-time, daemon produksi, & reliabilitas dapat dijalankan dengan:

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
- `test_init_config_subcommand_config_precedence_and_windows_hardening`: Verifikasi subcommand `init-config`, preservasi `--config`, normalisasi alamat Windows, dan installer 7-bit ASCII.
- `test_production_daemon_ipc_wan_roaming_and_2node_e2e`: Verifikasi Public/WAN IP discovery, WireGuard dynamic NAT endpoint roaming, serta pengujian E2E 3 proses daemon OS terpisah (`1 Controller Daemon` + `2 Client Daemon`).
- `test_zero_touch_onboarding_roaming_and_global_qkd_cli`: Verifikasi pendaftaran *zero-touch* (`join_token="auto"`), penghindaran tabrakan IP overlay, deteksi *roaming*, dan perintah CLI global `qkd`.
- `test_node_liveness_offline_transition_and_real_udp_probing`: Verifikasi metrik multi-probe UDP real (tanpa konstanta *dummy*), transisi instan ke `OFFLINE` & `OFFLINE_DOWN` saat `qkd stop` atau TTL *heartbeat* terlampaui, tampilan `N/A (OFFLINE)` pada QBER, serta pemulihan otomatis ke `ONLINE` & `DIRECT_P2P` saat peer kembali aktif.
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
# Menjalankan server Controller di latar belakang (Background Daemon)
qkd-sdwan-controller serve --daemon

# Atau menjalankan di foreground dengan konsol dashboard interaktif
qkd-sdwan-controller serve --dashboard

# Menghentikan background daemon Controller
qkd-sdwan-controller stop

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

#### Menggunakan Global Client CLI (`qkd` / `qkd-sdwan-client`)
Setelah instalasi, perintah singkat **`qkd`** tersedia secara global di terminal (Linux maupun Windows PowerShell/CMD):

```bash
# 1. Menyalakan / menghubungkan daemon Client ke Controller (Zero-Touch Auto-Enrollment)
qkd up http://201.18.208.72:8080

# 2. Membuka 4-Panel Interactive CLI Dashboard Client (Interaktif / Snapshot / Live Auto-Refresh)
qkd dashboard
qkd dashboard --once
qkd dashboard --interval 2.0

# 3. Melihat daftar peer SD-WAN & status tunnel WireGuard
qkd peers

# 4. Negosiasi kunci kuantum BB84 & injeksi PSK 256-bit (ke satu peer atau seluruh peer)
qkd rekey edge-vespoch
qkd rekey --all

# 5. Mengirim pesan teks & file biner terenkripsi ChaCha20Poly1305 P2P ke peer
qkd send edge-vespoch "Pesan rahasia ber-PSK BB84 256-bit"
qkd sendfile edge-vespoch /path/to/dokumen.pdf

# 6. Melihat daftar pesan/file masuk (Inbox) & menyimpan file terverifikasi SHA-256 ke disk
qkd inbox
qkd save 1 ./downloads

# 7. Menghentikan daemon Client (otomatis mengirim sinyal disconnect OFFLINE ke Controller)
qkd stop

# 8. Memeriksa status identitas & daemon endpoint lokal dalam format JSON
qkd status
```

---

## Tampilan CLI Dashboard Central Controller & Endpoint Client

### 1. Central Controller Dashboard (`qkd-ctl dashboard --once`)
Menampilkan status *liveness* setiap endpoint (`ONLINE`/`OFFLINE`), `Last Seen`, IP WAN & LAN, serta metrik kanal kuantum BB84 dan underlay (`RTT / Jitter / Loss`, `Throughput`, `Epoch/Aborts`, `ML Score`, `Updated`, dan `LinkStatus`):

```text
====================================================================================================================================
 QKD-SDWAN CENTRAL CONTROLLER — INTERACTIVE CLI DASHBOARD (BB84 QKD + ISOLATION FOREST ML) 
====================================================================================================================================
 Controller URL : http://127.0.0.1:8080                  | Timestamp          : 2026-11-07 08:28:18 UTC
 Overlay Subnet : 10.200.0.0/24                          | Nodes (On/Off/Tot) : 3 ONLINE / 0 OFFLINE / 3 TOTAL
 Active Links   : 6 HEALTHY / 6 TOTAL                    | Routing Directives : 6
------------------------------------------------------------------------------------------------------------------------------------
[1] CLUSTER ENROLLMENT JOIN TOKENS (Token-Based Zero-Touch Client Onboarding)
+--------------+-------------------+---------+-----------+--------+------------------------------------+
| Token ID     | Label             | Uses    | TTL Rem   | Status | Join Token (for Client Enrollment) |
+--------------+-------------------+---------+-----------+--------+------------------------------------+
| tok-88ce5288 | bootstrap-default | 3/10000 | 31530597s | ACTIVE | qkd-join-450fa730dbedf93c2947a017  |
+--------------+-------------------+---------+-----------+--------+------------------------------------+

[2] REGISTERED P2P SD-WAN ENDPOINT CLIENTS
+------------------+--------+-----------+-------------+----------------------+---------------+----------+-----------------------+-----------------------+
| Node ID          | Status | Last Seen | Overlay IP  | Underlay WG Endpoint | LAN IP        | QKD Port | Auth Token ID         | WG X25519 Public Key  |
+------------------+--------+-----------+-------------+----------------------+---------------+----------+-----------------------+-----------------------+
| edge-cloud-relay | ONLINE | 0.0s ago  | 10.200.0.10 | 201.18.208.72:51820  | 201.18.208.72 | 52820    | enrolled-tok-88ce5288 | IYRnZPkaUquDG8yw5W... |
| edge-hanmazaya   | ONLINE | 0.1s ago  | 10.200.0.11 | 114.10.149.143:51820 | 192.168.1.30  | 52820    | enrolled-tok-88ce5288 | jgNSp2JGH1bPIKVzAr... |
| edge-vespoch     | ONLINE | 1.0s ago  | 10.200.0.12 | 182.10.97.58:51820   | 192.168.1.2   | 52820    | enrolled-tok-88ce5288 | vzCu1oLp12Pny2Hp42... |
+------------------+--------+-----------+-------------+----------------------+---------------+----------+-----------------------+-----------------------+

[3] QUANTUM BB84 CHANNEL TELEMETRY & ISOLATION FOREST ANOMALY MONITOR
+------------------------------------+-------+-------+------------+----------------+------------------------+------------+--------------+----------+----------+------------+
| Directed Link                      | State | QBER  | Delta QBER | Key Rate (bps) | RTT / Jitter / Loss    | Throughput | Epoch/Aborts | ML Score | Updated  | LinkStatus |
+------------------------------------+-------+-------+------------+----------------+------------------------+------------+--------------+----------+----------+------------+
| edge-cloud-relay -> edge-hanmazaya | UP    | 1.26% | +0.00%     | 2689 bps       | 33.7ms / 15.9ms / 0.0% | 0.1 Mbps   | 154 / 0      | 0.444    | 0.1s ago | HEALTHY    |
| edge-cloud-relay -> edge-vespoch   | UP    | 2.03% | +0.00%     | 3025 bps       | 21.9ms / 0.3ms / 0.0%  | 0.2 Mbps   | 4 / 0        | 0.425    | 0.0s ago | HEALTHY    |
| edge-hanmazaya -> edge-cloud-relay | UP    | 1.26% | -0.07%     | 1708 bps       | 24.5ms / 1.1ms / 0.0%  | 0.2 Mbps   | 154 / 0      | 0.428    | 0.1s ago | HEALTHY    |
| edge-hanmazaya -> edge-vespoch     | UP    | 0.78% | +0.00%     | 2518 bps       | 50.1ms / 1.1ms / 0.0%  | 0.1 Mbps   | 69 / 0       | 0.401    | 0.1s ago | HEALTHY    |
| edge-vespoch -> edge-cloud-relay   | UP    | 2.03% | -0.64%     | 1887 bps       | 24.8ms / 3.8ms / 0.0%  | 0.2 Mbps   | 4 / 0        | 0.431    | 1.0s ago | HEALTHY    |
| edge-vespoch -> edge-hanmazaya     | UP    | 2.34% | +0.00%     | 1094 bps       | 52.5ms / 4.4ms / 0.0%  | 0.1 Mbps   | 4 / 0        | 0.461    | 1.0s ago | HEALTHY    |
+------------------------------------+-------+-------+------------+----------------+------------------------+------------+--------------+----------+----------+------------+

[4] ACTIVE P2P OVERLAY ROUTING DIRECTIVES (DIRECT_P2P vs RELAY_P2P)
+------------------------------------+------------+------------------+----------------------+------------+-------------+-------------------------------------+
| Source -> Target                   | RouteMode  | Next Hop         | Next Hop Endpoint    | LinkStatus | Force Rekey | Reason                              |
+------------------------------------+------------+------------------+----------------------+------------+-------------+-------------------------------------+
| edge-cloud-relay -> edge-hanmazaya | DIRECT_P2P | edge-hanmazaya   | 114.10.149.143:51820 | HEALTHY    | NO          | Direct P2P link healthy (cost=73.4) |
| edge-cloud-relay -> edge-vespoch   | DIRECT_P2P | edge-vespoch     | 182.10.97.58:51820   | HEALTHY    | NO          | Direct P2P link healthy (cost=22.6) |
| edge-hanmazaya -> edge-cloud-relay | DIRECT_P2P | edge-cloud-relay | 201.18.208.72:51820  | HEALTHY    | NO          | Direct P2P link healthy (cost=27.2) |
| edge-hanmazaya -> edge-vespoch     | DIRECT_P2P | edge-vespoch     | 182.10.97.58:51820   | HEALTHY    | NO          | Direct P2P link healthy (cost=52.8) |
| edge-vespoch -> edge-cloud-relay   | DIRECT_P2P | edge-cloud-relay | 201.18.208.72:51820  | HEALTHY    | NO          | Direct P2P link healthy (cost=34.3) |
| edge-vespoch -> edge-hanmazaya     | DIRECT_P2P | edge-hanmazaya   | 114.10.149.143:51820 | HEALTHY    | NO          | Direct P2P link healthy (cost=63.5) |
+------------------------------------+------------+------------------+----------------------+------------+-------------+-------------------------------------+
====================================================================================================================================
```

### 2. Ketika Salah Satu Endpoint Dimatikan (`qkd stop` / Offline)
Saat service pada salah satu endpoint berhenti (atau tidak mengirim *heartbeat* > 6 detik), status node langsung berubah menjadi `OFFLINE`, nilai QBER berubah menjadi `N/A (OFFLINE)`, `Key Rate` menjadi `0 bps`, `Loss` menjadi `100.0%`, `LinkStatus` menjadi `OFFLINE_DOWN`, dan rute menuju node tersebut diubah ke `QUARANTINED`:

```text
| edge-vespoch     | OFFLINE | 2.2s ago  | 10.200.0.12 | 182.10.97.58:51820   | 192.168.1.2   | 52820    |
...
| edge-cloud-relay -> edge-vespoch   | DOWN  | N/A (OFFLINE) | -      | 0 bps   | DOWN / - / 100.0%     | 0.0 Mbps | OFFLINE_DOWN |
| edge-hanmazaya -> edge-vespoch     | DOWN  | N/A (OFFLINE) | -      | 0 bps   | DOWN / - / 100.0%     | 0.0 Mbps | OFFLINE_DOWN |
```
