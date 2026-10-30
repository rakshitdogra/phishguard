# 🛡️ PhishGuard
### Intelligent Phishing Detection & Browser Protection

PhishGuard is a phishing detection and browser security solution designed to help users identify suspicious URLs, malicious websites, and potentially fraudulent emails before interacting with them.

It combines browser-level protection, email analysis, URL risk assessment, and threat intelligence integrations to provide users with actionable security insights.

---

## ✨ Key Features

- Phishing URL Detection
- Real-Time Link Analysis
- Pre-Navigation Protection
- URL Sanitization
- Gmail Integration
- Email File Analysis (`.eml` and `.txt`)
- Sender Impersonation Detection
- Attachment Risk Detection
- Threat Intelligence Integration
- Custom Blocklist & Allowlist
- Risk Scoring
- Explainable Threat Analysis
- Backend API Integration
- Privacy-Focused Architecture

---

## 🚀 Overview

Phishing attacks often rely on deceptive URLs, impersonated senders, malicious attachments, and social engineering techniques. PhishGuard aims to reduce these risks by analyzing suspicious digital content and presenting understandable security assessments.

The platform consists of:

1. **Browser Extension** – Provides link inspection, Gmail analysis, and browser-level security features.
2. **Backend Analysis Engine** – Processes submitted URLs and email data to generate risk assessments.
3. **Threat Intelligence Services** – Integrates with external security services for additional reputation checks.
4. **Custom Security Rules** – Supports configurable domain blocklists and allowlists.

---

## 🧩 How It Works

```text
             USER
               |
               v
       BROWSER EXTENSION
               |
       +-------+--------+
       |                |
       v                v
   URL ANALYSIS     EMAIL ANALYSIS
       |                |
       +-------+--------+
               |
               v
        BACKEND API
               |
       +-------+--------+
       |                |
       v                v
  DETECTION ENGINE  THREAT INTELLIGENCE
       |                |
       +-------+--------+
               |
               v
         RISK ASSESSMENT
               |
               v
       SECURITY RESULTS
```

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript / Next.js |
| Browser Extension | Chrome Extension APIs |
| Backend | Next.js API Routes |
| Threat Intelligence | VirusTotal API |
| URL Reputation | Google Safe Browsing API |
| Data Exchange | JSON / REST API |
| Configuration | Environment Variables |

---

## 📁 Project Structure

```text
PhishGuard/
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   ├── background.js
│   │
│   └── content/
│       ├── gmail.js
│       └── hover.js
│
├── app/
│   └── api/
│       └── analyze/
│           └── route.js
│
├── public/
├── README.md
├── package.json
└── .env.example
```

*The structure above is a representative layout. Adjust directory names to match the actual repository.*

---

## ⚙️ Getting Started

### Prerequisites

- Node.js (LTS recommended)
- npm
- Google Chrome
- VirusTotal API key (optional)
- Google Safe Browsing API key (optional)

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
cd PhishGuard
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env.local` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
PHISHGUARD_OFFLINE_MODE=false
```

Keep API keys private. Never expose them in frontend code or commit `.env.local` to GitHub.

### 4. Start the Development Server

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

### 5. Install the Chrome Extension

1. Open `chrome://extensions/` in Google Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the extension directory containing `manifest.json`.
5. Open the PhishGuard extension.
6. Configure the backend URL if required.
7. Start analyzing suspicious links and supported email files.

---

## 🔌 API Integration

The extension communicates with the backend analysis service.

### Analyze Endpoint

```http
POST /api/analyze
Content-Type: application/json
```

The endpoint accepts email or URL analysis data according to the backend implementation and returns a security assessment.

---

## 🔐 Security & Privacy

- API keys are stored on the backend.
- Untrusted email HTML is not directly rendered.
- Email files are parsed for analysis.
- External threat intelligence services are optional.
- Analysis results should be treated as security indicators, not absolute guarantees.

---

## ⚠️ Current Limitations

- Threat intelligence results depend on external API availability and configuration.
- Heuristic detection may produce false positives or miss sophisticated attacks.
- Gmail extraction depends on the structure of the Gmail interface.
- Email attachment filename analysis does not constitute full malware scanning of binary attachment contents.
- A low-risk result does not guarantee that a URL or email is safe.

---

## 🔮 Future Enhancements

- Advanced machine-learning-based phishing classification.
- Full attachment malware scanning.
- Improved sender authentication analysis.
- Expanded browser and email client support.
- Centralized threat intelligence dashboard.
- Domain reputation history and analytics.
- Enhanced reporting and security recommendations.

---

## 🎯 Project Objective

To make everyday browsing and email communication safer through accessible phishing detection, explainable risk assessments, and proactive browser-level protection.

---

## 👨‍💻 Contributing

Contributions, suggestions, and bug reports are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Open a Pull Request.

---

## 📄 License

Add your preferred open-source license before distributing the project. For example, MIT License.

---

**PhishGuard — Detect. Analyze. Protect.**
