# AuthGuard Decision Tree & Threat Analyzer 🛡️⚡

An interactive browser based tool to help you chose the correct Authentication (AuthN) and Authorization (AuthZ) flow for your application.

---

## ✨ Key Features

- **🌐 Sleek Landing Portal Homepage:** A premium, glassmorphic dashboard workspace allowing architects to choose between entering the **AuthN (Identity)** or **AuthZ (Access)** domain.
- **🧠 Interactive Decision Wizards:** Walk step-by-step through identity scenarios, stable role mappings, contextual attributes, or graph-based relationships with attack-based security notes.
- **🎨 Live Dynamic SVG Flowcharts:** Vector graphics dynamically clear and redraw nodes (circles for questions, rounded rects for decisions) and connecting bezier curves, highlighting visited paths and active states in real-time.

---

## 🗺️ Architectural Structure

The analyzer features two distinct, fully-functional decision workspaces:

### 1. Authentication Domain (AuthN)
Designed for evaluating human-initiated or machine-initiated identities:
- **Human Callers:** First-party vs. third-party apps, SSR session designs (HttpOnly, SameSite=Lax sessions), or Single-Page Apps (SPA) memory-token/refresh-cookie storage with PKCE verification.
- **Machine Callers:** Service-to-service internal cloud meshes utilizing Vault-stored Client Credentials, network-level Mutual TLS (mTLS), or Private Key JWT cryptographically-bound assertions.
- **MFA Policy Controls:** Evaluates admin bounds, sensitive action step-up auth, or context/risk-based factors contextually.

### 2. Authorization Domain (AuthZ)
Enforces granular access control models and mitigates object-level (BOLA) and function-level failures:
- **OAuth Scopes:** Course-grained token-level operation claims (best for partner and machine API boundaries).
- **RBAC (Role-Based):** Stable, function-based role hierarchies embedded in verified JWT claims.
- **ABAC (Attribute-Based):** Fine-grained contextual validation matching attributes from user, resource, action, and environment simultaneously.
- **ReBAC (Relationship-Based):** Graph-based access inheritance based on resource relations (e.g., project -> resource -> comment).
- **Embedded Tenant & Function Safeguards:** Non-negotiable database tenant query predicates, token-derived isolation, method-level verb validations, and explicit administrative endpoint guards.

---

## 🚀 Quick Start

Launch the security workspace immediately on your local machine:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/API-AuthN-AuthZ-Descision-Tree.git
   cd API-AuthN-AuthZ-Descision-Tree
   ```

2. **Run it locally:**
   - Double-click `index.html` to load the application directly in any modern browser using the `file://` protocol.
   - Alternatively, serve it via a simple server for complete, seamless console executions (e.g. `npx serve`, Live Server VS Code extension, or `python -m http.server`).
