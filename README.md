# **Developer Vulnerability Scanner - Documentation**  
**Version 1.0**  

---

## **📌 Table of Contents**  
1. [Introduction](#-introduction)  
2. [Features](#-features)  
3. [Getting Started](#-getting-started)  
   - [Web-Based Scanning](#web-based-scanning)  
   - [Local NPM Scanner](#local-npm-scanner)  
4. [API Reference](#-api-reference)  
5. [Security & Permissions](#-security--permissions)  
6. [Troubleshooting](#-troubleshooting)  
7. [FAQs](#-faqs)  
8. [Contributing](#-contributing)  

---

## **🌟 Introduction**  
The **Developer Vulnerability Scanner (DVS)** is a security tool that helps developers detect vulnerabilities in their code **before deployment**. It offers two scanning methods:  
1. **Web-Based (GitHub Repo Scanning)** – Submit a GitHub URL for remote analysis.  
2. **Local NPM Scanner** – Install a CLI tool to scan projects locally and view results in a dashboard.  

Built with **Vite (React), Node.js, and Express**, DVS integrates with **GitHub, npm audit, and security linters** to provide real-time vulnerability reports.  

---

## **✨ Features**  
✅ **Static Code Analysis** – Detects XSS, SQLi, hardcoded secrets, and more.  
✅ **Dependency Scanning** – Checks `package.json` for known vulnerabilities.  
✅ **Interactive Dashboard** – Visualizes security issues with severity levels.  
✅ **CI/CD Ready** – Can be integrated into GitHub Actions.  
✅ **Local Development Support** – Scan projects offline with the NPM CLI.  

---

## **🚀 Getting Started**  

### **Web-Based Scanning**  
1. **Sign in with GitHub**  
   - Visit [DVS Dashboard](https://your-scanner.app) → Click **"Login with GitHub"**.  
   - Grant access to repositories (required for scanning).  

2. **Submit a Repo for Scanning**  
   - Enter a **GitHub repo URL** (e.g., `https://github.com/username/repo`).  
   - Click **"Scan Now"**.  

3. **View Results**  
   - The dashboard displays:  
     - **Critical/High/Medium/Low** vulnerabilities.  
     - **Affected files** and **code snippets**.  
     - **Remediation suggestions**.  

---

### **Local NPM Scanner**  
#### **Installation**  
```bash
npm install -g your-scanner  # Global install (recommended)
# OR
npm install your-scanner --save-dev  # Project-level install
```

#### **Usage**  
1. **Run a Scan**  
   ```bash
   cd your-project
   your-scanner scan
   ```
   - Scans:  
     - `package.json` (npm audit)  
     - Source code (ESLint, Semgrep)  

2. **View Dashboard**  
   - Automatically opens **`http://localhost:3000`** with results.  
   - Example output:  
     ```
     🚀 Scan completed!  
     🔍 Found 12 vulnerabilities (3 critical).  
     🌐 Opening dashboard at http://localhost:3000...
     ```

---

## **🔌 API Reference**  
### **1. GitHub Repo Scan**  
**Endpoint:** `POST /api/scan`  
**Request:**  
```json
{
  "repoUrl": "https://github.com/user/repo",
  "accessToken": "ghp_..."  # (Optional if logged in)
}
```
**Response:**  
```json
{
  "status": "success",
  "issues": [
    {
      "type": "dependency",
      "severity": "high",
      "package": "lodash",
      "version": "4.17.15",
      "fix": "Upgrade to 4.17.21"
    }
  ]
}
```

### **2. Local Scan (CLI)**  
| Command | Description |
|---------|-------------|
| `your-scanner scan` | Scans current directory. |
| `your-scanner scan --dir ./path` | Scans a specific folder. |
| `your-scanner --version` | Checks installed version. |

---

## **🔒 Security & Permissions**  
- **GitHub Access**: Requires `repo` scope (for private repos).  
- **Data Handling**:  
  - **Web scans**: Temporary clone (deleted after scan).  
  - **Local scans**: No data leaves your machine.  

---

## **🛠 Troubleshooting**  
| Issue | Fix |
|-------|-----|
| **"GitHub rate limit exceeded"** | Wait 1 hour or use a PAT. |
| **"npm audit failed"** | Run `npm install` first. |
| **Dashboard not opening** | Manually visit `http://localhost:3000`. |

---

## **❓ FAQs**  
**Q: Does it work with private repos?**  
✅ Yes, if you grant access via GitHub OAuth.  

**Q: Can I use this in CI/CD?**  
✅ Yes! A **GitHub Action** is coming soon.  

**Q: What languages are supported?**  
- JavaScript/TypeScript (full support).  
- Python, Go (beta).  

---

## **👥 Contributing**  
Want to improve DVS?  
1. Fork the repo:  
   ```bash
   git clone https://github.com/your-scanner/core
   ```
2. Submit a PR with:  
   - New security rules  
   - UI improvements  
   - Bug fixes  

---

## **📜 License**  
MIT © 2024 Mahlet Belay  

---

### **📢 Need Help?**  
Contact: **support@your-scanner.app**  
GitHub: **[github.com/your-scanner](https://github.com/your-scanner)**  
