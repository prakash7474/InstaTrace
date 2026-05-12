# Secure TLS Traffic Analyzer CLI

## Overview
A terminal-based network monitoring and defensive threat detection project for **authorized/local/lab** environments. This tool performs **TLS/DNS/HTTP metadata analysis** from live captures or offline PCAPs.

> Security note: This project does **not** decrypt third-party traffic and does **not** attempt interception beyond authorized capture. It only analyzes packet metadata present in captures.

## Features
- Live packet capture (pyshark/tshark-based)
- Offline PCAP analysis
- TLS metadata extraction (version, cipher suite, SNI, handshake type)
- DNS parsing (queries + response IPs)
- HTTP parsing (method, host, path, status)
- Detection modules:
  - Port scan heuristics
  - DDoS heuristics
  - Suspicious IP scoring
  - ML anomalies (Isolation Forest)
- Real-time terminal UI (colorized output)
- Logging: packets, TLS, alerts
- Text report export

## Architecture
- `capture/`: capture & interface detection
- `parser/`: TLS/DNS/HTTP parsing
- `detection/`: detectors + ML anomaly model
- `utils/`: logging + colors + banner
- `reports/`: exported summaries

## Installation (Linux/Ubuntu/WSL)
```bash
cd tls-cli-analyzer
bash setup.sh
```

## Usage
Run the CLI:
```bash
python3 main.py --help
python3 main.py live
python3 main.py pcap --pcap ./pcaps/sample.pcap
python3 main.py alerts
python3 main.py export --out ./reports/report.txt
python3 main.py train-ml
```

### Live capture permissions
Depending on your environment, you may need permissions to capture packets (e.g., running with sudo or granting capture capabilities). Only do this in authorized labs.

## Feature Added: Instagram-like DM AES-GCM demo (metadata-triggered locally)

This project includes an educational AES-256-GCM encrypt/decrypt utility that builds an Instagram-like DM JSON payload.

In addition, a metadata-only detector (`InstagramDMCryptoDetector`) can trigger locally (no real Instagram decryption) and logs an alert after running a local encrypt/decrypt verification cycle.

- New module: `crypto/instagram_dm_encryptor.py`
- Dependency: `cryptography`

### CLI verification
Run:
```bash
python3 main.py dm-crypto-verify --text "Hello, this is a secret DM!"
```

> Note: The capture/analysis pipeline does **not** decrypt third-party traffic. Any “integration” is metadata-based and runs the encrypt/decrypt utility locally for verification.

## Future Improvements
- Stronger TLS feature extraction per handshake
- Better DDoS classifier using time-series features
- Optional integration with Elasticsearch/Grafana for dashboards
- Additional protocol parsers (QUIC, SMTP, etc.)


# Secure TLS Traffic Analyzer CLI

## Overview
A terminal-based network monitoring and defensive threat detection project for **authorized/local/lab** environments. This tool performs **TLS/DNS/HTTP metadata analysis** from live captures or offline PCAPs.

> Security note: This project does **not** decrypt third-party traffic and does **not** attempt interception beyond authorized capture. It only analyzes packet metadata present in captures.

## Features
- Live packet capture (pyshark/tshark-based)
- Offline PCAP analysis
- TLS metadata extraction (version, cipher suite, SNI, handshake type)
- DNS parsing (queries + response IPs)
- HTTP parsing (method, host, path, status)
- Detection modules:
  - Port scan heuristics
  - DDoS heuristics
  - Suspicious IP scoring
  - ML anomalies (Isolation Forest)
- Real-time terminal UI (colorized output)
- Logging: packets, TLS, alerts
- Text report export

## Architecture
- `capture/`: capture & interface detection
- `parser/`: TLS/DNS/HTTP parsing
- `detection/`: detectors + ML anomaly model
- `utils/`: logging + colors + banner
- `reports/`: exported summaries

## Installation (Linux/Ubuntu/WSL)
```bash
cd tls-cli-analyzer
bash setup.sh
```

## Usage
Run the CLI:
```bash
python3 main.py --help
python3 main.py live
python3 main.py pcap --pcap ./pcaps/sample.pcap
python3 main.py alerts
python3 main.py export --out ./reports/report.txt
python3 main.py train-ml
```

### Live capture permissions
Depending on your environment, you may need permissions to capture packets (e.g., running with sudo or granting capture capabilities). Only do this in authorized labs.

## Screenshots
- [Placeholder] Terminal UI screenshot
- [Placeholder] Alert feed screenshot

## Feature Added: Instagram-like DM AES-GCM demo (metadata-triggered locally)

This project includes an educational AES-256-GCM encrypt/decrypt utility that builds an Instagram-like DM JSON payload.

- New module: `crypto/instagram_dm_encryptor.py`
- Dependency: `cryptography`

### CLI verification
Run:
```bash
python3 main.py dm-crypto-verify --text "Hello, this is a secret DM!"
```

> Note: The capture/analysis pipeline does **not** decrypt third-party traffic. Any “integration” is metadata-based and runs the encrypt/decrypt utility locally for verification.

## Future Improvements
- Stronger TLS feature extraction per handshake
- Better DDoS classifier using time-series features
- Optional integration with Elasticsearch/Grafana for dashboards
- Additional protocol parsers (QUIC, SMTP, etc.)


