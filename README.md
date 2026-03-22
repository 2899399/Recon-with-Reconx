# 🔍 ReconX — Full Reconnaissance Tool

A professional-grade Python reconnaissance tool for cybersecurity professionals and students. Works on **Kali Linux** and **Windows CMD**.

## 🚀 Features

| Module | Details |
|--------|---------|
| 🌐 DNS & IP Info | Domain resolution, reverse DNS, all A records |
| 📍 GeoIP & ISP | Country, city, ISP, ASN, coordinates |
| 🔓 Port Scanner | 25+ common ports with threading for speed |
| 🖥️ Web Server & Stack | Server type, OS hints, powered-by, security headers |
| 🗄️ Database Detection | MySQL, PostgreSQL, MongoDB, Redis, MSSQL & more |
| 💾 Report Export | Save full results to a timestamped `.txt` file |

## 🛠️ Requirements

- Python 3.x
- Internet connection
- No external libraries needed (built-in modules only)

## ▶️ Usage

### Basic Scan
```bash
python3 reconx.py -t example.com
```

### Scan an IP
```bash
python3 reconx.py -t 8.8.8.8
```

### Save Report to File
```bash
python3 reconx.py -t example.com --save
```

### Help
```bash
python3 reconx.py --help
```

## 📸 Example Output

```
[1/5] DNS & IP Information
  [+] Target     : example.com
  [+] Resolved IP: 93.184.216.34
  [+] Reverse DNS: Not found

[2/5] GeoIP & Network Info
  [+] Country    : United States (US)
  [+] City       : Los Angeles
  [+] ISP        : Edgecast Inc.

[3/5] Port Scan & Service Detection
  [+] Port 80     OPEN   -> HTTP
  [+] Port 443    OPEN   -> HTTPS

[4/5] Web Server & Technology Stack
  [+] Web Server  : ECS (lax/...)
  [+] OS Hint     : Linux
  Security Headers:
    [✓] HSTS
    [✗] CSP — MISSING

[5/5] Database Detection
  [-] No database ports found open
```

## 🧠 What I Learned

- DNS resolution and reverse DNS lookup
- Multi-threaded port scanning with `concurrent.futures`
- HTTP header analysis for fingerprinting
- GeoIP lookup via public API
- Argparse for CLI tools
- Real-world recon methodology used in pentesting

## ⚠️ Disclaimer

This tool is for **educational and authorized use only**.  
Do not use it on systems you do not own or have explicit permission to test.  
Unauthorized scanning may violate laws in your country.

## 📚 Tech Used

- Python 3.x
- `socket` — DNS & port scanning
- `urllib` — HTTP requests
- `concurrent.futures` — Multi-threaded scanning
- `argparse` — CLI interface
- `json` — API response parsing
- [ip-api.com](http://ip-api.com) — Free GeoIP API

## 👨‍💻 Author

Parveen Kumar

---
⭐ If you found this useful, give it a star!
