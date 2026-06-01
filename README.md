# AuthGuard Decision Tree & Threat Analyzer 🛡️⚡

An interactive, premium, web-based flowchart and state machine designed to help software engineers, security professionals, and architects navigate complex Authentication (AuthN) architectures and automatically embed critical security controls.

The repository is named **`API-AuthN-AuthZ-Descision-Tree`** to reflect current AuthN capabilities and upcoming expansions into granular Authorization (AuthZ) mechanisms.

---

## ✨ Key Features

- **🧠 Interactive Decision Wizard:** Traverses complex authentication scenarios, analyzing architectures step-by-step with real-time feedback.
- **🎨 Dynamic SVG Flowchart Visualizer:** Live path tracing highlights active decisions, visited nodes, and future choices as you interact with the tree.
- **⚡ Proactive MFA Policy Injection:** Automatically embeds and displays Multi-Factor Authentication (MFA) policy guidelines and mitigates associated threats dynamically inside terminal nodes.
- **🗃️ Security Threat & Attack Mitigator:** Connects design outcomes to real-world attack vectors (XSS cookie theft, CSRF, PKCE code interception, service key leakage).
- **📝 Automated Security Audits:** Generate, review, copy, and download custom, comprehensive markdown audit reports of your architecture paths.
- **🎵 Retro-Futuristic Synth Sounds:** Dynamic audio feedback powered by the browser's native Web Audio API.

---

## 🗺️ Architectural Structure

The analyzer is structured into two main lanes of authentication flow, preparing the ground for future AuthZ (authorization) rules:

### Lane A: Human Callers (Authentication & MFA)
Designed for human-initiated access to resources through web browser or mobile client applications:
1. **First-Party vs. Third-Party Scope:** Determines OAuth delegation vs. direct authentication bounds.
2. **Server-Side Rendered (SSR) Sessions:** Focuses on secure HttpOnly, SameSite=Lax/Strict session design to prevent CSRF and XSS.
3. **Single Page Apps (SPAs) & Mobile Clients:** Recommends memory-stored tokens, HttpOnly refresh cookies, and strict Proof Key for Code Exchange (PKCE) implementations to block code hijacking.
4. **Automated MFA Safeguards:** Programmatically attaches step-up, risk-based, and administrator MFA policy directives right into the chosen workflow.

### Lane B: Machine Callers (Service-to-Service)
A zero-trust model for internal service workloads or external third-party API integrations:
1. **Internal S2S Workloads:** Identifies standard, high-assurance, or zero-trust boundaries using Client Credentials, Mutual TLS (mTLS), or Private Key JWT authentication.
2. **External Integrations:** Recommends header-bound API keys, client credentials, or network-level mTLS based on security compliance thresholds.

---

## 🛠️ Technology Stack

Built with 100% standard, modern, zero-dependency technologies for ultimate speed and visual customization:
- **Core:** Semantic HTML5 & Modern ES6 JavaScript.
- **Visuals:** Vector SVG rendering canvas with absolute position mapping and coordinate balancing.
- **Aesthetics:** CSS3 Custom Properties, neon dark/light theme, custom glassmorphism panels, and GPU-accelerated transition animations.
- **Audio:** Web Audio API sound synthesis.

---

## 🚀 Quick Start

Since this is a lightweight, zero-dependency frontend application, you can run it immediately without complex compilation setups:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/API-AuthN-AuthZ-Descision-Tree.git
   cd API-AuthN-AuthZ-Descision-Tree
   ```

2. **Run it locally:**
   - Simply double-click `index.html` to open it directly in your browser.
   - Alternatively, serve it using any simple dev server (e.g., Live Server extension in VS Code, `npx serve`, or `python -m http.server`).

---

## 🔮 Roadmap (Future AuthZ Expansions)
Future releases will expand this repository's decision state machine to support:
- **Role-Based Access Control (RBAC):** Designing secure role hierarchies and permissions.
- **Attribute-Based Access Control (ABAC):** Policy design matching user, environmental, and resource factors.
- **OAuth 2.0 Scopes & Grants:** Mapping API endpoints to custom scopes (`read:profile`, `write:settings`) and verifying token signatures downstream.
