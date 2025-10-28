# Sentinel-FIM 🔐
A Python File Integrity Monitor built for cybersecurity learning — detects file changes, creates secure baselines, and reports added, modified, and deleted files.

---

## 🧠 Features
- Baseline creation using SHA-256 hashing  
- Change detection for added / modified / deleted files  
- JSON reporting with clear CLI output  
- Watch mode for real-time monitoring  
- `.sentinelignore` support to skip files or folders  

---

## ⚙️ Usage
```bash
python sentinel_fim.py init C:\path\to\folder
python sentinel_fim.py scan C:\path\to\folder
python sentinel_fim.py watch C:\path\to\folder --interval 5
