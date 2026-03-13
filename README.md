# Duo Admin API OAuth 2.1 Proxy

A production-grade, asynchronous authentication proxy for the Duo Admin API. This service bridges standard **OAuth 2.1 / OpenID Connect** authentication with Duo's custom HMAC-SHA1 signature mechanism, enabling secure, audited, and granular access to Duo administrative functions.

## 🚀 Features

*   **OAuth 2.1 & OIDC Integration:** Uses Duo's native SSO for user authentication, supporting the modern Authorization Code Flow with PKCE.
*   **Dynamic Client Registration (DCR):** Securely relay registration requests to Duo SSO, allowing clients to programmatically obtain their own credentials.
*   **Hierarchical RBAC:** Fine-grained scope enforcement (`action:resource`) allowing for "Least Privilege" access (e.g., `read:users`, `update:settings`).
*   **Real-Time Security:** Immediate access revocation by verifying user status with Duo's `/userinfo` endpoint on every request.
*   **Production-Ready Performance:**
    *   **Asynchronous:** Built on FastAPI and httpx for non-blocking I/O.
    *   **Connection Pooling:** Reuses TCP/SSL connections to Duo API.
    *   **Distributed Caching:** Supports Redis for shared session/revocation state across multiple instances.
*   **Interactive Documentation:** Automatically generates a Swagger UI mapped to your OAuth 2.1 flow via your provided OpenAPI spec.
*   **Observability:** Structured audit logging that maps Duo API actions to specific OIDC identities.
*   **Resilience:** Automatic retries for transient network errors and smart handling of Duo's 429 rate limits.

## 🛠 Project Structure

```text
├── main.py                 # Core proxy and OIDC logic
├── scripts/
│   ├── setup.py            # Interactive configuration utility
│   └── discover_integrations.py # Tool to explore Duo API structures
├── deploy/
│   ├── Dockerfile          # Production container definition
│   ├── docker-compose.yml  # Multi-container orchestration (Proxy + Redis)
│   └── gunicorn_conf.py    # Production process manager config
├── .env.template           # Documented configuration template
├── requirements.txt        # Python dependencies
└── certs/                  # Generated SSL certificates (git-ignored)
```

## 🚦 Getting Started

### 1. Prerequisites
*   Python 3.10+ or Docker
*   A Duo Admin account with:
    *   **Admin API** application (with "Grant read information" enabled)
    *   **OAuth 2.1 / OIDC** application (Beta)

### 2. Configuration
Run the interactive setup script from the root to generate your `.env` file and optional SSL certificates:
```bash
python scripts/setup.py
```

### 3. Deployment

#### Development Mode
```bash
pip install -r requirements.txt
python main.py
```

#### Production Mode (Docker)
```bash
docker-compose -f deploy/docker-compose.yml up --build -d
```
> **Note:** Set `GUNICORN_WORKERS=2` or `4` in your `.env` for containerized deployments to avoid spawning excessive processes on large host machines.

## 🔒 Security Posture

### Scope Hierarchy
The proxy supports both **Master** and **Granular** scopes:

| Type | Format | Description |
| :--- | :--- | :--- |
| **Master** | `duo-admin-api:read` | Read access to ALL resources. |
| **Granular** | `duo-admin-api:read:users` | Read access ONLY to users. |
| **Action** | `duo-admin-api:create:groups` | Permission to create groups. |

### API Protection
The proxy protects itself using:
*   **Rate Limiting:** 100 requests per minute per IP (configurable).
*   **Session Security:** 1-hour rolling sessions with secure, signed cookies.
*   **Bearer Support:** Validates standard OIDC Bearer JWTs for CLI/System integrations.

## 📖 API Documentation
Once the proxy is running, navigate to `http://localhost:8000/docs` (or your configured port/HTTPS URL) to access the interactive Swagger UI. You will be prompted to log in via Duo SSO before the documentation is revealed.

### Dynamic Client Registration
If `PROXY_ENABLE_DCR` is enabled, you can register new OIDC clients via:
`POST /register` with a standard OIDC client metadata payload.

## 📜 License
MIT

## 🤖 Agent Team
This project is managed by a specialized team of Gemini sub-agents. They work primarily from GitHub Issues to evolve and maintain the proxy:

*   **Project Manager:** Triage, task delegation, and progress tracking.
*   **Proxy Architect:** Core FastAPI logic, HMAC signing, and performance.
*   **Identity Guard:** OIDC 2.1, RBAC policies, and real-time revocation.
*   **DX Specialist:** Swagger UI, DCR automation, and documentation.
*   **SRE Specialist:** Docker, Redis, setup automation, and reliability.
