/* -------------------------------------------------------------
 * AuthGuard Tree JS Controller
 * Logic for State Management, Dynamic SVG Drawing, Audio Synth,
 * Multi-Flow Portal Routing, and Custom Security Audit Report.
 * ------------------------------------------------------------- */

// Synthesize retro-futuristic synth UI sounds using Web Audio API
const playSound = (type) => {
    try {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (!AudioContextClass) return;
        const ctx = new AudioContextClass();
        
        // Simple synth audio elements
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        
        if (type === 'click') {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(500, ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(200, ctx.currentTime + 0.08);
            gain.gain.setValueAtTime(0.04, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.08);
            osc.start();
            osc.stop(ctx.currentTime + 0.08);
        } else if (type === 'success') {
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(300, ctx.currentTime);
            osc.frequency.setValueAtTime(600, ctx.currentTime + 0.08);
            osc.frequency.setValueAtTime(900, ctx.currentTime + 0.16);
            gain.gain.setValueAtTime(0.04, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
            osc.start();
            osc.stop(ctx.currentTime + 0.3);
        } else if (type === 'back') {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(300, ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(150, ctx.currentTime + 0.1);
            gain.gain.setValueAtTime(0.04, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.1);
            osc.start();
            osc.stop(ctx.currentTime + 0.1);
        }
    } catch (e) {
        // Suppress audio context errors (e.g. browser autoplay restriction)
    }
};

// 1. The Decision Tree Database (Fully derived from raw specs)
const MFA_RECOMMENDATION = {
    mfaPolicies: [
        { name: 'Always for Admin Operations', desc: 'Any operation that creates/modifies/deletes users, changes permissions, accesses bulk data, or touches configuration.' },
        { name: 'Step-up Auth for Sensitive Actions', desc: 'User is already authenticated, but a specific high-value action triggers a fresh MFA challenge. Do not protect only the login — protect the action.' },
        { name: 'Risk-based MFA', desc: 'New device, new location, unusual time, high-value operation — trigger MFA contextually. Requires an IdP that supports this (Okta, Entra ID, Auth0 all do).' }
    ],
    threats: [
        {
            name: 'MFA only at login, not at action level',
            critical: true,
            desc: 'An attacker who steals a session token (XSS, token sidejacking) gets an already-MFA\'d session. They can perform any action without being challenged again. Step-up auth at the action level means even a stolen session cannot execute privileged operations without a fresh factor.'
        }
    ]
};

const AUTHZ_RECOMMENDATION = {
    multiTenancy: [
        { name: 'Token-Derived Tenant ID', desc: 'Tenant ID must come from the cryptographically verified token — never from request parameters, headers, or request bodies to avoid spoofing.' },
        { name: 'Non-Negotiable Query Filters', desc: 'Every database query must enforce tenant filtering (e.g., SELECT * FROM findings WHERE id = ? AND tenant_id = ?).' },
        { name: 'Explicit Cross-Tenant Testing', desc: 'Verify isolation borders directly: authenticate as Tenant A, try to request Tenant B\'s resources, and confirm the system returns 404 (not 403) so as not to confirm existence.' }
    ],
    functionProtection: [
        { name: 'Explicit Check on Every Endpoint', desc: 'Enforce an active authorization check on all paths; no endpoint should be "public" by default.' },
        { name: 'Admin/Management Borders', desc: 'Enforce elevated roles explicitly on administration boundaries (/api/admin/*). Never rely on security through obscurity (hidden UI links).' },
        { name: 'HTTP Method Validation', desc: 'Check method-level actions explicitly. GET /api/findings can be open, but DELETE /api/findings must demand elevated permissions.' }
    ],
    threats: [
        {
            name: 'Tenant ID Spoofing in Request Body (BOLA / IDOR)',
            critical: true,
            desc: 'If an API extracts the tenant_id from the request body payload (e.g., POST /api/findings { tenant_id: "victim-corp" }), any attacker can easily view or corrupt other tenants\' data. This is a textbook BOLA vulnerability.'
        },
        {
            name: 'Broken Function Level Access (OWASP API5)',
            critical: true,
            desc: 'Privileged admin endpoints are left completely unprotected under the assumption that since there is no link in the UI, normal users cannot see them. Attackers scan common directories and execute them directly with normal user tokens.'
        }
    ]
};

const DECISION_TREE = {
    'start': {
        id: 'start',
        branch: 'START — Authentication Flow',
        type: 'question',
        title: 'Authentication Scenario Selection',
        text: 'What type of caller is requesting access to your system? Walk this tree once for each distinct caller type (e.g., human users or automated machine clients) you identified in your architecture.',
        notes: 'How to Read This Tree: Each node is a question. Each branch is an answer with a decision outcome and the attack reasoning behind it. Work through every question in order — do not skip ahead.',
        choices: [
            { text: 'Branch A — Human Caller (Browser or Mobile)', next: 'A1', desc: 'Authentication on behalf of a human user logging into an interface.' },
            { text: 'Branch B — Machine Caller (S2S or Partner)', next: 'B1', desc: 'Direct service-to-service calls or external system-level API integrations.' }
        ]
    },
    
    // --- Branch A: Human Callers ---
    'A1': {
        id: 'A1',
        branch: 'Branch A — Human Caller',
        type: 'question',
        title: 'A1. First-Party or Third-Party Application?',
        text: 'Is this a first-party application (you own both the frontend client and the backend API)?',
        notes: 'This question determines whether you need a full OAuth 2.0 delegation flow or whether a simpler direct first-party authentication is appropriate.',
        choices: [
            { text: 'YES — First Party', next: 'A2', desc: 'Your own frontend calling your own API. No third-party delegation needed.' },
            { text: 'NO — Third Party', next: 'A5', desc: 'A third-party application requesting access to your user\'s resources.' }
        ]
    },
    'A2': {
        id: 'A2',
        branch: 'Branch A — Human Caller',
        type: 'question',
        title: 'A2. Frontend Architecture Design',
        text: 'Is the frontend a server-rendered web application or a Client-Side Single-Page Application (SPA)?',
        notes: 'Server-rendered applications can leverage backend-held sessions securely, whereas SPAs run entirely in the browser context with no default secure credentials storage.',
        choices: [
            { text: 'Server-Rendered Web App', next: 'A3', desc: 'The server controls the page rendering and session lifecycle.' },
            { text: 'SPA (React, Vue, Angular, etc.)', next: 'A4', desc: 'Browser-driven frontend, making asynchronous backend API calls.' }
        ]
    },
    'A3': {
        id: 'A3',
        branch: 'Branch A — Human Caller',
        type: 'decision',
        title: 'A3. Server-Rendered App — Session Design',
        decisionText: 'Use server-side sessions with HttpOnly Secure SameSite=Lax cookies. The session ID must be a random opaque string — never the user ID, never a JWT. Session state lives server-side (e.g. Redis or Database). Short session lifetime (e.g. 30 min idle timeout). CSRF protection via SameSite cookie attribute and a synchronized CSRF token for state-changing operations.',
        threats: [
            {
                name: 'Without SameSite — CSRF Attack',
                critical: false,
                desc: 'An attacker tricks the victim\'s browser into sending an authenticated request to your API from a malicious page. The cookie rides along because browsers send cookies automatically. SameSite=Lax blocks this for non-top-level navigation. SameSite=Strict blocks it completely but breaks cross-site links.'
            },
            {
                name: 'Without HttpOnly — XSS Cookie Theft',
                critical: true,
                desc: 'A single XSS (Cross-Site Scripting) vulnerability anywhere on the domain lets attacker-controlled JavaScript read document.cookie and exfiltrate the session ID. Making cookies HttpOnly makes the cookie invisible to browser JavaScript entirely.'
            }
        ]
    },
    'A4': {
        id: 'A4',
        branch: 'Branch A — Human Caller',
        type: 'decision',
        title: 'A4. SPA — Token Design',
        decisionText: 'Store the access token in JavaScript memory (a module-level variable — NOT localStorage, NOT sessionStorage). Hold the refresh token in an HttpOnly Secure SameSite=Strict cookie. The SPA cannot read the refresh token — it just makes silent refresh calls to your auth endpoint and the browser attaches the cookie automatically. Access token lifetime: 15 minutes. Use PKCE even for first-party SPAs.',
        threats: [
            {
                name: 'localStorage access tokens — XSS Theft',
                critical: true,
                desc: 'Any injected script can call localStorage.getItem(\'access_token\') and POST it to an attacker\'s server. An HttpOnly cookie is immune to this because JavaScript cannot access it. Memory storage loses the token on refresh — which is why you need a refresh token in a cookie to restore it silently.'
            },
            {
                name: 'No PKCE for SPAs — Code Interception',
                critical: true,
                desc: 'If a browser extension, malicious redirect, or XSS captures the authorization code in the URL, it can be exchanged for tokens. Without PKCE, the code alone is enough. With PKCE, the code is worthless without the code_verifier that was never transmitted publicly.'
            }
        ]
    },
    'A5': {
        id: 'A5',
        branch: 'Branch A — Human Caller',
        type: 'question',
        title: 'A5. Client Secret Storage Capability',
        text: 'Can the client application securely hold and protect a client secret?',
        notes: 'Server-side backends can keep secrets hidden. Browser clients and mobile apps are distributed environments where a static secret can be extracted by any user or attacker.',
        choices: [
            { text: 'YES — Server-side Web App', next: 'A5_yes', desc: 'Traditional web app backend capable of securely calling secret-vaults.' },
            { text: 'NO — Mobile App or SPA', next: 'A5_no', desc: 'Code runs directly on user hardware, meaning secrets cannot remain hidden.' }
        ]
    },
    'A5_yes': {
        id: 'A5_yes',
        branch: 'Branch A — Human Caller',
        type: 'decision',
        title: 'OAuth 2.0 Auth Code Flow + Secret + PKCE',
        decisionText: 'Use OAuth 2.0 Authorization Code Flow + client secret + PKCE. Conduct back-channel token exchange. Maintain dynamic CSRF state parameters. Refer to OAuth 2.0 specs for complete implementation guidelines.',
        threats: [
            {
                name: 'Implicit Flow for SPAs (Legacy) — Token in URL',
                critical: true,
                desc: 'The access token appeared directly in the URL fragment. It lands in browser history, referrer headers sent to third-party resources on the page, and proxy logs. The attack surface is every outbound request from the callback page. The Implicit Flow is deprecated — never use it.'
            }
        ]
    },
    'A5_no': {
        id: 'A5_no',
        branch: 'Branch A — Human Caller',
        type: 'decision',
        title: 'OAuth 2.0 Auth Code Flow + PKCE Only',
        decisionText: 'Use OAuth 2.0 Authorization Code Flow + PKCE only. Do not use client secrets. Implement OS-level secure storage (Keychain for iOS, Keystore for Android) to store tokens. Refer to OAuth 2.0 notes for PKCE details.',
        threats: [
            {
                name: 'Implicit Flow for SPAs (Legacy) — Token in URL',
                critical: true,
                desc: 'The access token appeared directly in the URL fragment. It lands in browser history, referrer headers sent to third-party resources on the page, and proxy logs. The attack surface is every outbound request from the callback page. The Implicit Flow is deprecated — never use it.'
            }
        ]
    },
    
    // --- Branch B: Machine Callers ---
    'B1': {
        id: 'B1',
        branch: 'Branch B — Machine Caller',
        type: 'question',
        title: 'B1. Service Ownership & Trust boundary',
        text: 'Is this machine caller your own internal service, or an external third-party system?',
        notes: 'Internal services within your cloud environment can use private networks or secure meshes. External machines interact across the public internet and require formal credentials.',
        choices: [
            { text: 'Your Own Service', next: 'B2', desc: 'Service-to-service communication within your own secure infrastructure.' },
            { text: 'External Third Party', next: 'B4', desc: 'A partner, customer, or developer system calling your exposed API.' }
        ]
    },
    'B2': {
        id: 'B2',
        branch: 'Branch B — Machine Caller',
        type: 'question',
        title: 'B2. Session Context Analysis',
        text: 'Is there an end-user context involved in this service call?',
        notes: 'A service call either acts on behalf of a specific user (delegated access) or acts as itself with its own identity (service identity).',
        choices: [
            { text: 'Acting on Behalf of a User', next: 'B2_user', desc: 'The service received a user\'s access token and is forwarding a call downstream.' },
            { text: 'Acting as Itself (Service Identity)', next: 'B3', desc: 'No user context. Background job, scheduled task, internal automation.' }
        ]
    },
    'B2_user': {
        id: 'B2_user',
        branch: 'Branch B — Machine Caller',
        type: 'decision',
        title: 'Delegated Access — Token Forwarding or Exchange',
        decisionText: 'Use token forwarding (pass the user token downstream) or token exchange (RFC 8693 — acquire a new narrowly-scoped token for the downstream service). Never use the service\'s own master credentials for user-context calls.',
        threats: [
            {
                name: 'Using Service Credentials for User Context',
                critical: true,
                desc: 'Forwarding calls with a master service credential bypasses user-level permission checks. If the downstream service assumes all requests are pre-authorized, it may expose data the original user was never allowed to see.'
            }
        ]
    },
    'B3': {
        id: 'B3',
        branch: 'Branch B — Machine Caller',
        type: 'question',
        title: 'B3. Service Identity Security Level',
        text: 'How high is the security bar and regulatory compliance level for this machine connection?',
        notes: 'Standard applications use credentials. Zero-trust networks or high-risk financial/health databases demand hardware/cryptographic bound identity verification.',
        choices: [
            { text: 'Standard Internal Services', next: 'B3_standard', desc: 'Baseline security credentials, vault-managed secrets.' },
            { text: 'High-assurance / Zero-trust', next: 'B3_high', desc: 'Cryptographically bound credentials, network isolation.' },
            { text: 'Very High Assurance (Financial/Healthcare)', next: 'B3_very_high', desc: 'Double-layer transport and application level cryptographic identities.' }
        ]
    },
    'B3_standard': {
        id: 'B3_standard',
        branch: 'Branch B — Machine Caller',
        type: 'decision',
        title: 'OAuth 2.0 Client Credentials Flow',
        decisionText: 'Implement OAuth 2.0 Client Credentials Flow. Store client_id + client_secret securely in a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager). Rotate secrets on a schedule. Enforce tightly-scoped tokens.',
        threats: [
            {
                name: 'Hardcoded client secrets in service code',
                critical: true,
                desc: 'A developer commits a config file to GitHub. An automated scanner harvests it within minutes. The attacker now has a service identity and can make any API calls that service is authorised for — often with broad internal scopes that far exceed what a user token would grant. The blast radius of a service credential leak is typically larger than a user credential leak.'
            },
            {
                name: 'Overly broad service scopes',
                critical: false,
                desc: 'A data-processing service is granted read:all because it was easier than figuring out the specific tables it needs. When that service is compromised, the attacker can read everything. Service tokens should be scoped to the minimum operations that service genuinely performs.'
            }
        ]
    },
    'B3_high': {
        id: 'B3_high',
        branch: 'Branch B — Machine Caller',
        type: 'decision',
        title: 'Mutual TLS (mTLS) Service Identity',
        decisionText: 'Enforce Mutual TLS (mTLS). Each service holds an X.509 certificate signed by an internal Certificate Authority (CA). No shared secrets exist — service identity is cryptographically tied to the certificate. Gateway or service mesh validates the cert on every connection.',
        threats: [
            {
                name: 'Overly broad service scopes on connection',
                critical: false,
                desc: 'Even with cryptographically verified mTLS, if authorization scopes are omitted, a compromised service can issue arbitrary commands. Apply minimal RBAC / scoping on top of the mTLS connection.'
            }
        ]
    },
    'B3_very_high': {
        id: 'B3_very_high',
        branch: 'Branch B — Machine Caller',
        type: 'decision',
        title: 'Private Key JWT + mTLS Transport',
        decisionText: 'Use Private Key JWT (client_assertion) for token requests + mTLS for transport. This creates a double layer — the certificate proves network identity, the JWT assertion proves application identity at the token exchange.',
        threats: [
            {
                name: 'Transport-only credential interception',
                critical: true,
                desc: 'If transport security (mTLS) is breached, credentials can be spoofed in simple flows. A Private Key JWT ensures application-level authentication so that raw secrets are never sent across the wire, neutralizing packet-capture risks.'
            }
        ]
    },
    'B4': {
        id: 'B4',
        branch: 'Branch B — Machine Caller',
        type: 'decision',
        title: 'B4. External Partner / Machine Design',
        decisionText: 'Issue API Keys for simple integrations where per-request identity is sufficient and user delegation is not involved. Implement OAuth 2.0 Client Credentials for integrations requiring granular, revocable, and auditable scopes. Enforce mTLS for high-assurance partner integrations (financial, healthcare, government) to guarantee cryptographic identity binding.',
        threats: [
            {
                name: 'API key in URL parameters (?api_key=abc123)',
                critical: true,
                desc: 'URL parameters appear in server access logs, browser history, referrer headers, and APM tools. Once logged, the key is accessible to anyone with log access — which is often a much wider group than intended. Always use headers for API keys, never URL parameters.'
            },
            {
                name: 'Single API key for all operations',
                critical: false,
                desc: 'If the key is compromised, the attacker has every permission the key has. Issue separate keys for separate integration points, each scoped to the minimum required operations. This limits the blast radius of any single key compromise.'
            }
        ]
    },
    
    // --- Branch Z: Authorization Flow ---
    'authz_start': {
        id: 'authz_start',
        branch: 'START — Authorization Flow',
        type: 'question',
        title: 'Authorization Model Selection',
        text: 'What type of client or transaction requires access validation inside your application?',
        notes: 'Access boundaries can vary along multiple dimensions: Role (job function), Resource ownership (creator), Organization/Tenant (multi-tenant boundaries), Attributes (clearance, context), or Relationships (graph membership). Select the primary caller type to start.',
        choices: [
            { text: 'Machine / Partner Integration (Operation-level)', next: 'Z_model_scopes', desc: 'Scope-based authorization where access control is coarse-grained (can do operation X).' },
            { text: 'Human User (Fine-grained or Resource-level)', next: 'Z_dimensions', desc: 'Access depends on user roles, tenant limits, environmental conditions, or relationships.' }
        ]
    },
    'Z_dimensions': {
        id: 'Z_dimensions',
        branch: 'Branch Z — Authorization Flow',
        type: 'question',
        title: 'Select Fine-Grained Access Control Dimension',
        text: 'What primary factor determines whether a human user should be allowed to access a specific resource in your system?',
        notes: 'Your system may have multiple dimensions. Start by selecting the primary model, and the analyzer will automatically attach Multi-Tenancy and Function-Level mitigations to your chosen design.',
        choices: [
            { text: 'Job Function (Stable User Roles)', next: 'Z_model_rbac', desc: 'Access control is primarily determined by job function (e.g., viewer, analyst, admin) with a small, stable set of roles.' },
            { text: 'Multiple Contextual Attributes', next: 'Z_model_abac', desc: 'Access depends on environment variables (time, device trust) or user attributes (clearance) checked simultaneously.' },
            { text: 'Resource Relationships / Graphs', next: 'Z_model_rebac', desc: 'Access depends on the user\'s specific relationship to a resource hierarchy (e.g., project member, assessment owner).' }
        ]
    },
    'Z_model_scopes': {
        id: 'Z_model_scopes',
        branch: 'Branch Z — Authorization Flow',
        type: 'decision',
        title: 'OAuth 2.0 Scope-Based Coarse-Grained Authorization',
        decisionText: 'Implement OAuth 2.0 scope checks on the resource server. Verify that the client\'s verified token carries the required scope (e.g. read:findings, write:alerts) before executing the operation. Ensure scopes are tightly-scoped and client credentials flow secrets are stored in a dedicated vault.',
        threats: [
            {
                name: 'Scope-Based Auth Alone for User-Facing APIs',
                critical: true,
                desc: 'A user token with scope "read:findings" can read ALL findings regardless of tenant or owner. Scopes are coarse-grained (can do X) and do NOT enforce object-level limits. You need scopes PLUS RBAC/ABAC/ReBAC for user-facing applications.'
            }
        ]
    },
    'Z_model_rbac': {
        id: 'Z_model_rbac',
        branch: 'Branch Z — Authorization Flow',
        type: 'decision',
        title: 'Role-Based Access Control (RBAC)',
        decisionText: 'Assign users to predefined roles (e.g. viewer, analyst, admin) and map permissions to those roles. Embed the active role inside verified JWT claims and validate the role at every endpoint. This is the optimal, stable starting point for internal application interfaces.',
        threats: [
            {
                name: 'RBAC without Object-Level Checks (BOLA / IDOR)',
                critical: true,
                desc: 'A simple role check confirms the user is a "soc_analyst", but doesn\'t verify if finding "9999" belongs to their organization. An analyst at Tenant A can call /api/findings/9999 belonging to Tenant B. You must combine RBAC with non-negotiable database tenant/owner predicates.'
            }
        ]
    },
    'Z_model_abac': {
        id: 'Z_model_abac',
        branch: 'Branch Z — Authorization Flow',
        type: 'decision',
        title: 'Attribute-Based Access Control (ABAC)',
        decisionText: 'Evaluate access dynamically using policy rules against a set of attributes from the user (clearance, dept), resource (classification), action, and environment (time, device trust). Best when access requires satisfying multiple complex dimensions simultaneously.',
        threats: [
            {
                name: 'ABAC Policy Sprawl & Administration Complexity',
                critical: false,
                desc: 'As policy counts grow, understanding what a user can access becomes highly complex. Mitigate this "policy sprawl" by enforcing strict unit tests for policies, conducting regular reviews, and using simulation tools to test access scenarios.'
            }
        ]
    },
    'Z_model_rebac': {
        id: 'Z_model_rebac',
        branch: 'Branch Z — Authorization Flow',
        type: 'decision',
        title: 'Relationship-Based Access Control (ReBAC)',
        decisionText: 'Enforce access boundaries based on a graph of relationships (e.g., project -> resource -> comment) and inheritance (a project member can view comments). Access flows directly from relationship checks (owner, member, contributor) on the specific object.',
        threats: [
            {
                name: 'ReBAC Graph Traversal Overhead & Latency',
                critical: true,
                desc: 'Evaluating graph paths for every API request can trigger extreme performance bottlenecks. Mitigate this by utilizing a high-performance graph database (e.g. Google Zanzibar model) or implementing aggressive, highly-optimized caching for relationship checks.'
            }
        ]
    }
};

// 2. SVG Flow Chart Visualizations for both AuthN and AuthZ
const SVG_FLOWS = {
    'authn': {
        layout: {
            'start': { label: 'START', type: 'start', x: 300, y: 40 },
            'A1': { label: 'A1', type: 'question', x: 160, y: 130 },
            'A2': { label: 'A2', type: 'question', x: 80, y: 220 },
            'A3': { label: 'A3 (D)', type: 'decision', x: 35, y: 320 },
            'A4': { label: 'A4 (D)', type: 'decision', x: 125, y: 320 },
            'A5': { label: 'A5', type: 'question', x: 240, y: 220 },
            'A5_yes': { label: 'A5 (Y)', type: 'decision', x: 190, y: 320 },
            'A5_no': { label: 'A5 (N)', type: 'decision', x: 275, y: 320 },
            
            'B1': { label: 'B1', type: 'question', x: 440, y: 130 },
            'B2': { label: 'B2', type: 'question', x: 400, y: 220 },
            'B2_user': { label: 'B2 (U)', type: 'decision', x: 350, y: 320 },
            'B3': { label: 'B3', type: 'question', x: 450, y: 320 },
            'B3_standard': { label: 'B3 (Std)', type: 'decision', x: 390, y: 430 },
            'B3_high': { label: 'B3 (Hi)', type: 'decision', x: 450, y: 430 },
            'B3_very_high': { label: 'B3 (VHi)', type: 'decision', x: 510, y: 430 },
            'B4': { label: 'B4 (D)', type: 'decision', x: 530, y: 220 }
        },
        edges: [
            { from: 'start', to: 'A1', label: 'Human' },
            { from: 'start', to: 'B1', label: 'Machine' },
            { from: 'A1', to: 'A2', label: 'YES' },
            { from: 'A1', to: 'A5', label: 'NO' },
            { from: 'A2', to: 'A3', label: 'Server' },
            { from: 'A2', to: 'A4', label: 'SPA' },
            { from: 'A5', to: 'A5_yes', label: 'YES' },
            { from: 'A5', to: 'A5_no', label: 'NO' },
            
            { from: 'B1', to: 'B2', label: 'Internal' },
            { from: 'B1', to: 'B4', label: 'External' },
            { from: 'B2', to: 'B2_user', label: 'User' },
            { from: 'B2', to: 'B3', label: 'Machine' },
            { from: 'B3', to: 'B3_standard', label: 'Standard' },
            { from: 'B3', to: 'B3_high', label: 'High' },
            { from: 'B3', to: 'B3_very_high', label: 'ZeroTrust' }
        ]
    },
    'authz': {
        layout: {
            'authz_start': { label: 'START', type: 'start', x: 300, y: 40 },
            'Z_model_scopes': { label: 'Scopes', type: 'decision', x: 150, y: 160 },
            'Z_dimensions': { label: 'Z1', type: 'question', x: 450, y: 160 },
            'Z_model_rbac': { label: 'RBAC', type: 'decision', x: 340, y: 280 },
            'Z_model_abac': { label: 'ABAC', type: 'decision', x: 450, y: 280 },
            'Z_model_rebac': { label: 'ReBAC', type: 'decision', x: 560, y: 280 }
        },
        edges: [
            { from: 'authz_start', to: 'Z_model_scopes', label: 'Machine' },
            { from: 'authz_start', to: 'Z_dimensions', label: 'Human' },
            { from: 'Z_dimensions', to: 'Z_model_rbac', label: 'RBAC' },
            { from: 'Z_dimensions', to: 'Z_model_abac', label: 'ABAC' },
            { from: 'Z_dimensions', to: 'Z_model_rebac', label: 'ReBAC' }
        ]
    }
};

// 3. Application State variables
let currentFlow = 'authn'; // 'authn' or 'authz'
let currentNodeId = 'start';
let pathHistory = ['start'];

// 4. DOM Elements
const btnThemeToggle = document.getElementById('btn-theme-toggle');
const btnHome = document.getElementById('btn-home');

const wizardCard = document.getElementById('wizard-card');
const wizardTitle = document.getElementById('wizard-title');
const wizardText = document.getElementById('wizard-text');
const wizardNotes = document.getElementById('wizard-notes');
const wizardChoices = document.getElementById('wizard-choices');
const btnBack = document.getElementById('btn-back');
const btnRestart = document.getElementById('btn-restart');
const breadcrumbs = document.getElementById('breadcrumbs');

const reportModal = document.getElementById('report-modal');
const reportMarkdownContent = document.getElementById('report-markdown-content');
const btnCloseModal = document.getElementById('btn-close-modal');
const btnCopyReport = document.getElementById('btn-copy-report');
const btnDownloadReport = document.getElementById('btn-download-report');

// --- WIZARD RENDER LOGIC ---
const renderWizard = () => {
    const node = DECISION_TREE[currentNodeId];
    if (!node) return;

    // Set header badge
    const badge = wizardCard.querySelector('.step-badge');
    if (badge) badge.textContent = node.branch;

    // Set heading and body text
    wizardTitle.textContent = node.title;
    
    // Clear choices container
    wizardChoices.innerHTML = '';
    wizardText.innerHTML = '';

    if (node.type === 'question') {
        wizardText.textContent = node.text;

        // Render explanation notes if present
        if (node.notes) {
            wizardNotes.style.display = 'flex';
            wizardNotes.querySelector('.info-text').textContent = node.notes;
        } else {
            wizardNotes.style.display = 'none';
        }

        // Render branching options
        node.choices.forEach(choice => {
            const btn = document.createElement('button');
            btn.className = 'choice-option';
            btn.setAttribute('aria-label', `Choose: ${choice.text}`);
            btn.innerHTML = `
                <span class="choice-option-title">${choice.text}</span>
                ${choice.desc ? `<span class="choice-option-desc">${choice.desc}</span>` : ''}
            `;
            btn.addEventListener('click', () => {
                playSound('click');
                navigateTo(choice.next);
            });
            wizardChoices.appendChild(btn);
        });
    } else if (node.type === 'decision') {
        wizardNotes.style.display = 'none';

        // 1. Render the green decision recommendation card
        const decisionBox = document.createElement('div');
        decisionBox.className = 'decision-box';
        decisionBox.innerHTML = `
            <div class="decision-title-group">
                <span class="decision-badge">RECOMMENDED DESIGN</span>
                <h3 class="decision-heading">${node.title}</h3>
            </div>
            <p class="decision-text">${node.decisionText}</p>
        `;
        wizardText.appendChild(decisionBox);

        // 2. Render MFA Policies Checklist if Node is from AuthN flow
        if (node.mfaPolicies) {
            const mfaHeading = document.createElement('h3');
            mfaHeading.className = 'threats-section-title';
            mfaHeading.style.color = 'var(--accent-cyan)';
            mfaHeading.innerHTML = `💡 MFA Implementation Policies`;
            wizardChoices.appendChild(mfaHeading);

            const mfaList = document.createElement('div');
            mfaList.className = 'mfa-policies-list';
            node.mfaPolicies.forEach(policy => {
                const item = document.createElement('div');
                item.className = 'mfa-policy-item';
                item.innerHTML = `
                    <div class="policy-dot"></div>
                    <div class="policy-details">
                        <h4>${policy.name}</h4>
                        <p>${policy.desc}</p>
                    </div>
                `;
                mfaList.appendChild(item);
            });
            wizardChoices.appendChild(mfaList);
        }

        // 3. Render Tenant Isolation Checklist if Node has multiTenancy (AuthZ flow)
        if (node.multiTenancy) {
            const tenancyHeading = document.createElement('h3');
            tenancyHeading.className = 'threats-section-title';
            tenancyHeading.style.color = 'var(--accent-cyan)';
            tenancyHeading.innerHTML = `🛡️ Required Multi-Tenancy Isolation Bounds`;
            wizardChoices.appendChild(tenancyHeading);

            const tenancyList = document.createElement('div');
            tenancyList.className = 'mfa-policies-list';
            node.multiTenancy.forEach(policy => {
                const item = document.createElement('div');
                item.className = 'mfa-policy-item';
                item.innerHTML = `
                    <div class="policy-dot" style="background-color: var(--accent-cyan)"></div>
                    <div class="policy-details">
                        <h4>${policy.name}</h4>
                        <p>${policy.desc}</p>
                    </div>
                `;
                tenancyList.appendChild(item);
            });
            wizardChoices.appendChild(tenancyList);
        }

        // 4. Render Function Protection Checklist if Node has functionProtection (AuthZ flow)
        if (node.functionProtection) {
            const funcHeading = document.createElement('h3');
            funcHeading.className = 'threats-section-title';
            funcHeading.style.color = 'var(--accent-green)';
            funcHeading.innerHTML = `⚙️ Function-Level Access Protections`;
            wizardChoices.appendChild(funcHeading);

            const funcList = document.createElement('div');
            funcList.className = 'mfa-policies-list';
            node.functionProtection.forEach(policy => {
                const item = document.createElement('div');
                item.className = 'mfa-policy-item';
                item.innerHTML = `
                    <div class="policy-dot" style="background-color: var(--accent-green)"></div>
                    <div class="policy-details">
                        <h4>${policy.name}</h4>
                        <p>${policy.desc}</p>
                    </div>
                `;
                funcList.appendChild(item);
            });
            wizardChoices.appendChild(funcList);
        }

        // 5. Render Threat mitigations list
        if (node.threats && node.threats.length > 0) {
            const threatHeading = document.createElement('h3');
            threatHeading.className = 'threats-section-title';
            threatHeading.innerHTML = `
                <svg class="threat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                Threats Mitigated by This Decision
            `;
            wizardChoices.appendChild(threatHeading);

            node.threats.forEach((threat, index) => {
                const panel = document.createElement('div');
                panel.className = `threat-panel ${threat.critical ? 'critical' : ''}`;
                panel.innerHTML = `
                    <button class="threat-header-btn" aria-expanded="false" aria-label="Toggle Threat details for ${threat.name}">
                        <span>${threat.name}</span>
                        <svg class="threat-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"/>
                        </svg>
                    </button>
                    <div class="threat-body">
                        <p class="threat-desc">${threat.desc}</p>
                    </div>
                `;

                // Add expand/collapse event to panel button
                const btn = panel.querySelector('.threat-header-btn');
                btn.addEventListener('click', () => {
                    playSound('click');
                    const expanded = btn.getAttribute('aria-expanded') === 'true';
                    btn.setAttribute('aria-expanded', !expanded);
                    panel.classList.toggle('expanded');
                });
                
                wizardChoices.appendChild(panel);
            });
        }

        // 6. Render Action Buttons (Export Report or Return to Home)
        const actionsGroup = document.createElement('div');
        actionsGroup.className = 'wizard-actions-group';
        actionsGroup.style.marginTop = '30px';
        actionsGroup.style.display = 'flex';
        actionsGroup.style.flexWrap = 'wrap';
        actionsGroup.style.gap = '15px';

        const btnExport = document.createElement('button');
        btnExport.className = 'btn btn-primary';
        btnExport.id = 'btn-open-report';
        btnExport.innerHTML = `
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
                <polyline points="10 9 9 9 8 9"/>
            </svg>
            Export Security Report
        `;
        btnExport.addEventListener('click', () => {
            playSound('success');
            openReportModal();
        });
        actionsGroup.appendChild(btnExport);

        const btnGoHome = document.createElement('button');
        btnGoHome.className = 'btn btn-secondary';
        btnGoHome.innerHTML = `
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                <polyline points="9 22 9 12 15 12 15 22"/>
            </svg>
            Portal Home
        `;
        btnGoHome.addEventListener('click', () => {
            playSound('back');
            returnToLandingPortal();
        });
        actionsGroup.appendChild(btnGoHome);

        wizardChoices.appendChild(actionsGroup);
    }

    // Update bottom footer navigation buttons
    if (pathHistory.length > 1) {
        btnBack.removeAttribute('disabled');
        btnBack.classList.remove('disabled');
    } else {
        btnBack.setAttribute('disabled', 'true');
        btnBack.classList.add('disabled');
    }

    // Refresh breadcrumbs
    renderBreadcrumbs();
    
    // Refresh visual SVG state
    updateSVGState();
};

// --- BREADCRUMBS LOGIC ---
const renderBreadcrumbs = () => {
    breadcrumbs.innerHTML = '';
    
    pathHistory.forEach((nodeId, idx) => {
        const span = document.createElement('span');
        span.className = `breadcrumb-item ${nodeId === currentNodeId ? 'active' : ''}`;
        span.dataset.node = nodeId;
        
        let label = 'START';
        if (nodeId !== 'start' && nodeId !== 'authz_start') {
            const n = DECISION_TREE[nodeId];
            label = n ? n.title.split('.')[0] : nodeId;
        }
        
        span.textContent = label;
        span.addEventListener('click', () => {
            playSound('back');
            jumpToHistoryIndex(idx);
        });
        breadcrumbs.appendChild(span);
    });
};

// --- NAVIGATION FLOW CONTROLLER ---
const navigateTo = (nodeId) => {
    if (!DECISION_TREE[nodeId]) return;
    
    // Check if we are looping or going back
    const historyIndex = pathHistory.indexOf(nodeId);
    if (historyIndex !== -1) {
        pathHistory = pathHistory.slice(0, historyIndex + 1);
    } else {
        pathHistory.push(nodeId);
    }
    
    currentNodeId = nodeId;
    renderWizard();
};

const jumpToHistoryIndex = (index) => {
    if (index >= 0 && index < pathHistory.length) {
        pathHistory = pathHistory.slice(0, index + 1);
        currentNodeId = pathHistory[index];
        renderWizard();
    }
};

const stepBack = () => {
    if (pathHistory.length > 1) {
        playSound('back');
        pathHistory.pop();
        currentNodeId = pathHistory[pathHistory.length - 1];
        renderWizard();
    }
};

const restartTree = () => {
    playSound('click');
    if (currentFlow === 'authn') {
        currentNodeId = 'start';
        pathHistory = ['start'];
    } else if (currentFlow === 'authz') {
        currentNodeId = 'authz_start';
        pathHistory = ['authz_start'];
    }
    renderWizard();
};

// --- SVG STATIC RENDER & LIVE PATH HIGHLIGHTING ---
const setupSVGVisualizer = () => {
    const edgesGroup = document.getElementById('edges-group');
    const nodesGroup = document.getElementById('nodes-group');
    
    if (!edgesGroup || !nodesGroup) return;
    
    edgesGroup.innerHTML = '';
    nodesGroup.innerHTML = '';
    
    const activeFlowData = SVG_FLOWS[currentFlow];
    if (!activeFlowData) return;
    
    const layoutDetails = activeFlowData.layout;
    const edgesDetails = activeFlowData.edges;
    
    // 1. Draw connecting bezier edges
    edgesDetails.forEach(edge => {
        const fromNode = layoutDetails[edge.from];
        const toNode = layoutDetails[edge.to];
        if (!fromNode || !toNode) return;
        
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const midY = (fromNode.y + toNode.y) / 2;
        const d = `M ${fromNode.x} ${fromNode.y} C ${fromNode.x} ${midY}, ${toNode.x} ${midY}, ${toNode.x} ${toNode.y}`;
        
        path.setAttribute('d', d);
        path.setAttribute('class', 'tree-edge');
        path.setAttribute('id', `edge-${edge.from}-${edge.to}`);
        path.setAttribute('marker-end', 'url(#arrow)');
        
        edgesGroup.appendChild(path);
    });
    
    // 2. Draw nodes
    Object.keys(layoutDetails).forEach(nodeId => {
        const layout = layoutDetails[nodeId];
        const config = DECISION_TREE[nodeId] || { type: 'question' };
        
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `tree-node ${config.type}`);
        g.setAttribute('id', `node-${nodeId}`);
        g.setAttribute('data-node', nodeId);
        g.setAttribute('tabindex', '0');
        g.setAttribute('role', 'button');
        g.setAttribute('aria-label', `Navigate to ${config.title || layout.label}`);
        
        if (layout.type === 'start') {
            const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('x', layout.x - 30);
            rect.setAttribute('y', layout.y - 16);
            rect.setAttribute('width', 60);
            rect.setAttribute('height', 32);
            rect.setAttribute('rx', 8);
            rect.setAttribute('class', 'node-shape');
            g.appendChild(rect);
        } else if (config.type === 'question') {
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', layout.x);
            circle.setAttribute('cy', layout.y);
            circle.setAttribute('r', 18);
            circle.setAttribute('class', 'node-shape');
            g.appendChild(circle);
        } else if (config.type === 'decision') {
            const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('x', layout.x - 32);
            rect.setAttribute('y', layout.y - 16);
            rect.setAttribute('width', 64);
            rect.setAttribute('height', 32);
            rect.setAttribute('rx', 5);
            rect.setAttribute('class', 'node-shape');
            g.appendChild(rect);
        }
        
        // Add inside node labels
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', layout.x);
        text.setAttribute('y', layout.y + 4);
        text.setAttribute('class', 'node-text');
        text.textContent = layout.label;
        g.appendChild(text);
        
        // Click event on SVG nodes
        g.addEventListener('click', () => {
            playSound('click');
            navigateTo(nodeId);
        });
        
        // Keyboard triggering
        g.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                playSound('click');
                navigateTo(nodeId);
            }
        });
        
        nodesGroup.appendChild(g);
    });
};

const updateSVGState = () => {
    // 1. Reset all nodes & edges
    const allNodes = document.querySelectorAll('.tree-node');
    allNodes.forEach(node => {
        node.classList.remove('active', 'visited');
    });
    
    const allEdges = document.querySelectorAll('.tree-edge');
    allEdges.forEach(edge => {
        edge.classList.remove('active');
        edge.setAttribute('marker-end', 'url(#arrow)');
    });
    
    // 2. Mark active path nodes
    pathHistory.forEach(nodeId => {
        const nodeEl = document.getElementById(`node-${nodeId}`);
        if (nodeEl) nodeEl.classList.add('visited');
    });
    
    // Highlight the exact current node
    const currentNodeEl = document.getElementById(`node-${currentNodeId}`);
    if (currentNodeEl) currentNodeEl.classList.add('active');
    
    // 3. Highlight edges along path history
    for (let i = 0; i < pathHistory.length - 1; i++) {
        const from = pathHistory[i];
        const to = pathHistory[i + 1];
        
        // Highlight active connections
        const edgeEl = document.getElementById(`edge-${from}-${to}`);
        if (edgeEl) {
            edgeEl.classList.add('active');
            edgeEl.setAttribute('marker-end', 'url(#arrow-active)');
        }
    }
};

// --- REPORT MD EXPORT AND DOWNLOAD LOGIC ---
const generateMarkdownReport = () => {
    const isAuthN = currentFlow === 'authn';
    let report = `# ${isAuthN ? 'Authentication' : 'Authorization'} Audit Security Report\n`;
    report += `Generated on: ${new Date().toLocaleDateString()} — via AuthGuard Decision Tree Analyzer\n\n`;
    report += `## Audit Parameters & Path Logs\n`;
    
    pathHistory.forEach((nodeId, index) => {
        const node = DECISION_TREE[nodeId];
        if (node) {
            report += `${index + 1}. **${node.title}** (${node.branch})\n`;
            if (node.type === 'question') {
                const nextNodeId = pathHistory[index + 1];
                if (nextNodeId) {
                    // Find choice picked
                    const choice = node.choices.find(c => c.next === nextNodeId);
                    if (choice) {
                        report += `   - *Selection:* User selected **${choice.text}**\n`;
                    }
                }
            }
            report += `\n`;
        }
    });
    
    const finalNode = DECISION_TREE[currentNodeId];
    if (finalNode && finalNode.type === 'decision') {
        report += `## Recommended Mechanism Design\n`;
        report += `> [%s]\n`.replace('%s', '!IMPORTANT');
        report += `> **${finalNode.title}**\n`;
        report += `> ${finalNode.decisionText}\n\n`;
        
        if (finalNode.mfaPolicies) {
            report += `### Required MFA Implementation Policies\n`;
            finalNode.mfaPolicies.forEach(policy => {
                report += `- **${policy.name}:** ${policy.desc}\n`;
            });
            report += `\n`;
        }

        if (finalNode.multiTenancy) {
            report += `### Required Multi-Tenancy Isolation Bounds\n`;
            finalNode.multiTenancy.forEach(policy => {
                report += `- **${policy.name}:** ${policy.desc}\n`;
            });
            report += `\n`;
        }

        if (finalNode.functionProtection) {
            report += `### Required Function-Level Access Protections\n`;
            finalNode.functionProtection.forEach(policy => {
                report += `- **${policy.name}:** ${policy.desc}\n`;
            });
            report += `\n`;
        }
        
        if (finalNode.threats && finalNode.threats.length > 0) {
            report += `## Threats Mitigated & Attack Vectors Addressed\n`;
            finalNode.threats.forEach(threat => {
                report += `### ${threat.critical ? '🚨 [CRITICAL]' : '⚠️ [WARNING]'} ${threat.name}\n`;
                report += `${threat.desc}\n\n`;
            });
        }
    } else {
        report += `## Status\n`;
        report += `*Decision flow audit is currently in progress. Work through every question to generate complete mitigation reports.*\n`;
    }
    
    return report;
};

const openReportModal = () => {
    const md = generateMarkdownReport();
    reportMarkdownContent.textContent = md;
    
    // Set modal title depending on flow
    document.getElementById('modal-title').textContent = currentFlow === 'authn' ? 'Authentication Audit Report' : 'Authorization Audit Report';
    
    reportModal.classList.add('active');
};

const closeReportModal = () => {
    playSound('back');
    reportModal.classList.remove('active');
};

const copyReportToClipboard = () => {
    playSound('success');
    const text = reportMarkdownContent.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('btn-copy-report');
        const originalText = btn.innerHTML;
        btn.innerHTML = `✓ Copied Successfully!`;
        setTimeout(() => {
            btn.innerHTML = originalText;
        }, 2000);
    }).catch(err => {
        alert('Failed to copy report: ' + err);
    });
};

const downloadReportFile = () => {
    playSound('success');
    const text = reportMarkdownContent.textContent;
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `auth-audit-report-${currentNodeId}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
};

// --- PORTAL ROUTER STATE TRANSITIONS ---
const startFlow = (flowType) => {
    currentFlow = flowType;
    if (flowType === 'authn') {
        currentNodeId = 'start';
        pathHistory = ['start'];
    } else if (flowType === 'authz') {
        currentNodeId = 'authz_start';
        pathHistory = ['authz_start'];
    }
    
    // Transition view panels
    document.getElementById('view-landing').classList.add('hidden');
    document.getElementById('view-analyzer').classList.remove('hidden');
    btnHome.classList.remove('hidden');
    
    // Set headers dynamically
    const titleText = flowType === 'authn' ? 'Interactive Authentication Flow' : 'Interactive Authorization Flow';
    document.getElementById('graph-title-text').textContent = titleText;
    
    // Render setup
    setupSVGVisualizer();
    renderWizard();
};

const returnToLandingPortal = () => {
    document.getElementById('view-analyzer').classList.add('hidden');
    document.getElementById('view-landing').classList.remove('hidden');
    btnHome.classList.add('hidden');
};

// --- INITIALIZE THE APP TABS & THEMES ---
const setupAppFramework = () => {
    // 1. Landing Portal route buttons
    document.getElementById('card-route-authn').addEventListener('click', () => {
        playSound('success');
        startFlow('authn');
    });
    
    document.getElementById('card-route-authz').addEventListener('click', () => {
        playSound('success');
        startFlow('authz');
    });
    
    // 2. Return to Portal Home buttons
    btnHome.addEventListener('click', () => {
        playSound('back');
        returnToLandingPortal();
    });
    
    // 3. Theme Toggle
    btnThemeToggle.addEventListener('click', () => {
        playSound('click');
        document.body.classList.toggle('light-theme');
        document.body.classList.toggle('dark-theme');
    });
    
    // 4. Wizard Footer navigation
    btnBack.addEventListener('click', stepBack);
    btnRestart.addEventListener('click', restartTree);
    
    // 5. Modal listeners
    btnCloseModal.addEventListener('click', closeReportModal);
    btnCopyReport.addEventListener('click', copyReportToClipboard);
    btnDownloadReport.addEventListener('click', downloadReportFile);
    
    // Hide modal on backdrop click
    reportModal.addEventListener('click', (e) => {
        if (e.target === reportModal) {
            closeReportModal();
        }
    });
};

// --- APP INITIALIZER BOOTSTRAP ---
document.addEventListener('DOMContentLoaded', () => {
    // Programmatically inject shared recommendations into respective decision databases
    
    // AuthN
    ['A3', 'A4', 'A5_yes', 'A5_no'].forEach(nodeId => {
        const node = DECISION_TREE[nodeId];
        if (node) {
            node.mfaPolicies = [...MFA_RECOMMENDATION.mfaPolicies];
            node.threats = [...(node.threats || []), ...MFA_RECOMMENDATION.threats];
        }
    });
    
    // AuthZ
    ['Z_model_scopes', 'Z_model_rbac', 'Z_model_abac', 'Z_model_rebac'].forEach(nodeId => {
        const node = DECISION_TREE[nodeId];
        if (node) {
            node.multiTenancy = [...AUTHZ_RECOMMENDATION.multiTenancy];
            node.functionProtection = [...AUTHZ_RECOMMENDATION.functionProtection];
            node.threats = [...(node.threats || []), ...AUTHZ_RECOMMENDATION.threats];
        }
    });

    setupAppFramework();
});
