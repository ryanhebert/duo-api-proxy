import os
import time
import hmac
import hashlib
import base64
import logging
import json
import asyncio
import urllib.parse
from typing import Optional, List
from contextlib import asynccontextmanager

import yaml
import httpx
import redis.asyncio as redis
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- Configuration & Environment ---
load_dotenv()

def get_env_required(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise RuntimeError(f"CRITICAL: Missing required environment variable: {key}")
    return val

# Validate default secrets
PROXY_SESSION_SECRET = os.getenv("PROXY_SESSION_SECRET", "change-me-in-production")
if PROXY_SESSION_SECRET == "change-me-in-production":
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("WARNING: Using default PROXY_SESSION_SECRET. This is INSECURE.")
    print("Please run setup.py or set a random string in your .env.")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

DUO_IKEY = os.getenv("DUO_IKEY")
DUO_SKEY = os.getenv("DUO_SKEY")
DUO_HOST = os.getenv("DUO_HOST")
DUO_SSO_CLIENT_ID = os.getenv("DUO_SSO_CLIENT_ID")
DUO_SSO_CLIENT_SECRET = os.getenv("DUO_SSO_CLIENT_SECRET")
DUO_SSO_WELL_KNOWN_URL = os.getenv("DUO_SSO_WELL_KNOWN_URL")
REDIS_URL = os.getenv("REDIS_URL")
PROXY_ENABLE_DCR = os.getenv("PROXY_ENABLE_DCR", "false").lower() == "true"
DCR_INITIAL_TOKEN = os.getenv("DCR_INITIAL_ACCESS_TOKEN")
OPENAPI_SPEC_PATH = os.getenv("OPENAPI_SPEC_PATH", "../duoMcp/duo-admin-api.yaml")
CACHE_TTL = int(os.getenv("REVOCATION_CHECK_CACHE_SECONDS", "30"))
PROXY_DEBUG = os.getenv("PROXY_DEBUG", "false").lower() == "true"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://localhost:8443,http://localhost:8000").split(",")

# --- Logging Setup ---
class ProxyLoggingFilter(logging.Filter):
    def filter(self, record):
        for field, default in [('user', 'SYSTEM'), ('method', 'LOG'), ('path', 'N/A')]:
            if not hasattr(record, field): setattr(record, field, default)
        return True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("duo-proxy")
logger.handlers.clear()
logger.propagate = False
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(user)s - %(method)s %(path)s - %(message)s"))
ch.addFilter(ProxyLoggingFilter())
logger.addHandler(ch)

def get_proxy_logger(user="SYSTEM", method="INFO", path="N/A"):
    return logging.LoggerAdapter(logger, {"user": user, "method": method, "path": path})

# --- Rate Limiting ---
limiter = Limiter(key_func=get_remote_address)

# --- Caching Layer ---
class CacheProvider:
    def __init__(self):
        self.redis = None
        self._local = {}

    async def connect(self):
        if REDIS_URL:
            try:
                self.redis = redis.from_url(REDIS_URL, decode_responses=True)
                await self.redis.ping()
                logger.info("Connected to Redis for distributed caching.")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}. Falling back to in-memory.")
                self.redis = None

    async def get(self, k):
        if self.redis: return await self.redis.get(k)
        item = self._local.get(k)
        return item['v'] if item and time.time() < item['e'] else None

    async def set(self, k, v, t):
        if self.redis: await self.redis.set(k, v, ex=t)
        else: self._local[k] = {'v': v, 'e': time.time() + t}

    async def close(self):
        if self.redis: await self.redis.close()

cache = CacheProvider()

# --- Duo HMAC Signing ---
def sign_duo_request(method, host, path, params, skey, ikey):
    # RFC 7231 requires GMT
    now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
    # Properly URL encode keys and values for the canonical string
    sorted_items = sorted(params.items())
    canon_params = "&".join([
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}" 
        for k, v in sorted_items
    ])
    
    canonical = "\n".join([now, method.upper(), host.lower(), path, canon_params])
    sig = hmac.new(skey.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha1).hexdigest()
    auth_header = f"Basic {base64.b64encode(f'{ikey}:{sig}'.encode('utf-8')).decode('utf-8')}"
    return auth_header, now

# --- Identity Helpers ---
def parse_scopes(data):
    if not data: return []
    raw = data.get('scope') or data.get('scp', '')
    if isinstance(raw, list): return [str(s) for s in raw]
    return [s for s in str(raw).split(' ') if s]

async def get_active_user_profile(token: str, app_state):
    """Refetches user info from Duo to ensure session is still valid."""
    k = f"proxy:rev:{hashlib.sha256(token.encode()).hexdigest()}"
    cached = await cache.get(k)
    if cached: return json.loads(cached)
    
    try:
        discovery = app_state.duo_discovery
        resp = await app_state.http_client.get(
            discovery["userinfo_endpoint"], 
            headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code == 200:
            payload = resp.json()
            await cache.set(k, json.dumps(payload), CACHE_TTL)
            return payload
    except Exception as e:
        logger.error(f"Userinfo verification failed: {e}")
    return None

async def validate_bearer_token(token: str, app_state):
    try:
        discovery = app_state.duo_discovery
        jwks_resp = await app_state.http_client.get(discovery["jwks_uri"])
        jwks = jwks_resp.json()
        
        issuer = DUO_SSO_WELL_KNOWN_URL.split("/.well-known")[0]
        payload = jwt.decode(
            token, jwks, algorithms=["RS256"], 
            issuer=issuer, 
            options={"verify_aud": not PROXY_ENABLE_DCR}
        )
        
        if PROXY_ENABLE_DCR and not payload.get("aud"):
            return None
            
        profile = await get_active_user_profile(token, app_state)
        return payload if profile else None
    except Exception as e:
        logger.warning(f"Bearer validation failed: {e}")
        return None

# --- Lifespan & App Setup ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Validation
    required = ["DUO_IKEY", "DUO_SKEY", "DUO_HOST", "DUO_SSO_CLIENT_ID", "DUO_SSO_CLIENT_SECRET", "DUO_SSO_WELL_KNOWN_URL"]
    for v in required: get_env_required(v)
    
    # Global HTTP Client with Retries
    app.state.http_client = httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(retries=3), 
        timeout=30.0
    )
    
    # Cache Duo OIDC Discovery
    try:
        resp = await app.state.http_client.get(DUO_SSO_WELL_KNOWN_URL)
        resp.raise_for_status()
        app.state.duo_discovery = resp.json()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch Duo OIDC Discovery: {e}")
    
    await cache.connect()
    logger.info(f"Duo Proxy Online | Target: {DUO_HOST} | Mode: {'Distributed' if REDIS_URL else 'Standalone'}")
    yield
    await cache.close()
    await app.state.http_client.aclose()

app = FastAPI(title="Duo Admin API Proxy", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ENABLE_DOCS = os.getenv("PROXY_ENABLE_DOCS", "true").lower() == "true"
if not ENABLE_DOCS: app.openapi_url = None

# Secure CORS: Use explicit allowlist for credentialed requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=PROXY_SESSION_SECRET, max_age=3600)

# --- OIDC ---
oauth = OAuth()
oauth.register(
    name='duo',
    client_id=DUO_SSO_CLIENT_ID,
    client_secret=DUO_SSO_CLIENT_SECRET,
    server_metadata_url=DUO_SSO_WELL_KNOWN_URL,
    client_kwargs={'scope': 'openid profile email duo-admin-api:read duo-admin-api:write', 'code_challenge_method': 'S256'}
)

@app.get("/login")
async def login(request: Request):
    return await oauth.duo.authorize_redirect(
        request, 
        str(request.url_for('auth_callback')), 
        resource=f"https://{DUO_HOST}"
    )

@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.duo.authorize_access_token(request, resource=f"https://{DUO_HOST}")
        user = token.get('userinfo')
        if user:
            # Merge scopes from both sources
            scopes = set(parse_scopes(token) + parse_scopes(user))
            user['scope'] = ' '.join(scopes)
            request.session['user'] = user
            request.session['access_token'] = token.get('access_token')
            get_proxy_logger(user=get_user_display_name(user)).info("OIDC Login Success")
        return RedirectResponse(url='/docs')
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed. Please try again.")

@app.get("/logout", include_in_schema=False)
async def logout(request: Request):
    request.session.clear()
    return HTMLResponse("<script>localStorage.clear(); sessionStorage.clear(); window.location.href = '/login';</script>")

@app.get("/")
async def root(request: Request):
    user = request.session.get('user')
    if not user: return RedirectResponse(url='/login')
    if not any(s.startswith("duo-admin-api:") for s in parse_scopes(user)):
        return {"error": "Missing duo-admin-api scopes", "user": user}
    return {"status": "Authorized", "user": user}

@app.post("/register", include_in_schema=False)
async def register_client(request: Request):
    if not PROXY_ENABLE_DCR: raise HTTPException(status_code=404)
    
    headers = {}
    if DCR_INITIAL_TOKEN:
        # Properly use the IAT if configured
        headers["Authorization"] = f"Bearer {DCR_INITIAL_TOKEN}"

    client = app.state.http_client
    try:
        discovery = app.state.duo_discovery
        reg_url = discovery.get("registration_endpoint") or f"{DUO_SSO_WELL_KNOWN_URL.split('/.well-known')[0]}/register"
        
        duo_resp = await client.post(reg_url, json=await request.json(), headers=headers)
        data = duo_resp.json()
        
        # Mask secret in logs
        log_data = data.copy()
        if "client_secret" in log_data: log_data["client_secret"] = "********"
        logger.info(f"DCR Success: {json.dumps(log_data)}")
        
        return JSONResponse(content=data, status_code=duo_resp.status_code)
    except Exception as e:
        logger.error(f"DCR failed: {e}")
        raise HTTPException(status_code=500, detail="Client registration failed")

# --- UI & Docs ---
def custom_openapi():
    if app.openapi_schema: return app.openapi_schema
    try:
        with open(OPENAPI_SPEC_PATH, "r") as f: schema = yaml.safe_load(f)
    except Exception:
        return get_openapi(title=app.title, version="1.0", routes=app.routes)

    resource_map = {
        "users": ["read", "create", "update", "delete"], "groups": ["read", "create", "update", "delete"],
        "phones": ["read", "create", "update", "delete"], "tokens": ["read", "create", "update", "delete"],
        "bypass_codes": ["read", "create", "delete"], "admins": ["read", "create", "update", "delete"],
        "integrations": ["read", "create", "update", "delete"], "logs": ["read"],
        "settings": ["read", "update"], "accounts": ["read"]
    }
    proxy_scopes = {"openid": "openid", "profile": "profile", "email": "email",
                    "duo-admin-api:read": "Master Read", "duo-admin-api:create": "Master Create",
                    "duo-admin-api:update": "Master Update", "duo-admin-api:delete": "Master Delete"}
    for r, vs in resource_map.items():
        for v in vs: proxy_scopes[f"duo-admin-api:{v}:{r}"] = f"{v} {r}"

    schema["info"]["title"] = "Duo Admin API Proxy"
    schema["info"]["description"] = "## Duo Admin API Proxy\nStandard OAuth 2.1 interface for the Duo Admin API."
    if PROXY_ENABLE_DCR:
        if "/register" not in schema["paths"]:
            schema["paths"]["/register"] = {"post": {"summary": "Dynamic Client Registration", "tags": ["DCR"], "responses": {"200": {"description": "OK"}}}}
    
    schema["servers"] = [{"url": "./"}]
    schema["components"]["securitySchemes"] = {"ProxyOAuth2": {"type": "oauth2", "flows": {"authorizationCode": {"authorizationUrl": "/login", "tokenUrl": "/auth/callback", "scopes": proxy_scopes}}}}
    schema["security"] = [{"ProxyOAuth2": []}]
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(request: Request):
    if not ENABLE_DOCS: raise HTTPException(status_code=404)
    user = request.session.get('user')
    if not user: return RedirectResponse(url='/login')
    
    scopes = parse_scopes(user)
    if not any(s.startswith("duo-admin-api:") for s in scopes):
        raise HTTPException(status_code=403, detail=f"Unauthorized. Missing duo-admin-api scopes.")

    scope_str = " ".join(["openid", "profile", "email"] + [s for s in scopes if s.startswith("duo-admin-api:")])
    
    html = f"""
    <!DOCTYPE html><html><head><link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <title>{app.title}</title><style>
        body {{ margin: 0; padding: 0; }}
        #proxy-header {{ background-color: #1b1b1b; color: white; padding: 10px 20px; display: flex; align-items: center; justify-content: space-between; font-family: sans-serif; border-bottom: 3px solid #4bfa4b; position: sticky; top: 0; z-index: 1000; }}
        .header-title {{ font-weight: bold; color: #4bfa4b; }}
        .custom-btn {{ padding: 6px 15px; border-radius: 4px; font-weight: bold; text-decoration: none; border: none; cursor: pointer; font-size: 13px; margin-left: 10px; }}
        .btn-logout {{ background: #fa4b4b; color: white !important; }}
        .btn-dcr {{ background: #4bfa4b; color: black !important; }}
        .btn-clear {{ background: #666; color: white !important; }}
    </style></head><body>
    <div id="proxy-header"><div class="header-title">Duo Admin API Proxy</div><div class="header-controls">
        <button id="clear-btn" class="custom-btn btn-clear">Clear Saved Client</button>
        <a href="/logout" class="custom-btn btn-logout">Logout</a>
        <button id="dcr-btn" class="custom-btn btn-dcr" style="display: {'inline-flex' if PROXY_ENABLE_DCR else 'none'}">Dynamic Registration</button>
    </div></div>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '/openapi.json', dom_id: '#swagger-ui', presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
                layout: "BaseLayout", deepLinking: true, oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
                persistAuthorization: true, usePkceWithAuthorizationCodeGrant: true
            }});
            ui.initOAuth({{ scopes: "{scope_str}", usePkceWithAuthorizationCodeGrant: true }});

            const fillModal = () => {{
                const cid = localStorage.getItem('proxy_dcr_client_id');
                const secret = localStorage.getItem('proxy_dcr_client_secret');
                if (!cid) return;
                const idIn = document.querySelector('input[name="client_id"]');
                const secIn = document.querySelector('input[name="client_secret"]');
                const cbs = document.querySelectorAll('.scope-checkbox');
                if (idIn && idIn.value !== cid) {{
                    idIn.value = cid;
                    idIn.dispatchEvent(new Event('change', {{ bubbles: true }}));
                }}
                if (secIn && secIn.value !== secret) {{
                    secIn.value = secret;
                    secIn.dispatchEvent(new Event('change', {{ bubbles: true }}));
                }}
                if (cbs.length > 0) cbs.forEach(cb => {{ if (!cb.checked) cb.click(); }});
            }};

            const poller = setInterval(fillModal, 500);
            
            document.getElementById('clear-btn').onclick = () => {{
                localStorage.clear();
                window.location.reload();
            }};

            const dcrBtn = document.getElementById('dcr-btn');
            if (dcrBtn) {{
                dcrBtn.onclick = async () => {{
                    const name = prompt("Client Name:", "Swagger-UI");
                    if (!name) return;
                    try {{
                        const resp = await fetch('/register', {{
                            method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ 
                                client_name: name, application_type: 'web', 
                                redirect_uris: [window.location.origin + '/docs', window.location.origin + '/docs/oauth2-redirect'] 
                            }})
                        }});
                        if (!resp.ok) throw new Error("Registration Failed");
                        const data = await resp.json();
                        localStorage.setItem('proxy_dcr_client_id', data.client_id);
                        localStorage.setItem('proxy_dcr_client_secret', data.client_secret || "");
                        alert("Success! Registered. Opening Modal...");
                        document.querySelector('.authorize').click();
                    }} catch (e) {{ alert(e.message); }}
                }};
            }}
        }};
    </script></body></html>
    """
    return HTMLResponse(html)

@app.get("/docs/oauth2-redirect", include_in_schema=False)
async def swagger_oauth2_redirect(request: Request):
    """Fixed OAuth2 redirect handler that parses URL parameters."""
    return HTMLResponse(f"""
        <!doctype html><html><body onload='run()'><script>
            function run() {{
                var oauth2 = window.opener.swaggerUIRedirectOauth2;
                var url = new URL(window.location.href);
                var params = {{}};
                url.searchParams.forEach((v, k) => params[k] = v);
                oauth2.callback({{auth: oauth2.auth, token: params, state: params.state}});
                window.close();
            }}
        </script></body></html>
    """)

# --- Proxy Core ---
@app.api_route("/admin/{version}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
@limiter.limit("100/minute")
async def duo_proxy(version: str, path: str, request: Request):
    client = app.state.http_client
    u, at = request.session.get('user'), request.session.get('access_token')
    auth = request.headers.get("Authorization")
    
    if not u and auth and auth.startswith("Bearer "):
        at = auth.split(" ")[1]
        u = await validate_bearer_token(at, app.state)
    elif u and at:
        u_refreshed = await get_active_user_profile(at, app.state)
        if not u_refreshed: 
            request.session.clear()
            raise HTTPException(status_code=401, detail="Session revoked or expired")
        u.update(u_refreshed)
    
    if not u: raise HTTPException(status_code=401, detail="Unauthorized")
    
    scopes = parse_scopes(u)
    method, parts = request.method, path.split('/')
    res = parts[0].lower()
    
    # Improved Action Inference
    if method == "GET": action = "read"
    elif method == "DELETE": action = "delete"
    elif method == "POST" and len(parts) == 1: action = "create"
    else: action = "update"
    
    if not (f"duo-admin-api:{action}" in scopes or f"duo-admin-api:{action}:{res}" in scopes):
        get_proxy_logger(user=get_user_display_name(u)).warning(f"Forbidden: Missing {action} scope")
        raise HTTPException(status_code=403, detail=f"Requires duo-admin-api:{action}")

    full_path = f"/admin/{version}/{path}"
    query_params = dict(request.query_params)
    
    # Duo requires form parameters to be signed for POST/PUT
    signing_params = query_params.copy()
    if method in ["POST", "PUT"]:
        try:
            form = await request.form()
            signing_params.update(dict(form))
        except Exception: pass
    
    sig, dt = sign_duo_request(method, DUO_HOST, full_path, signing_params, DUO_SKEY, DUO_IKEY)
    
    # Forward headers including Content-Type
    headers = {
        "Authorization": sig, 
        "Date": dt, 
        "User-Agent": "DuoProxy/8.0",
        "Content-Type": request.headers.get("Content-Type", "application/x-www-form-urlencoded")
    }
    
    try:
        pr = await client.request(
            method=method, 
            url=f"https://{DUO_HOST}{full_path}", 
            headers=headers, 
            params=query_params, 
            content=await request.body()
        )
        
        if pr.status_code == 429:
            return JSONResponse(pr.json(), 429, {"Retry-After": pr.headers.get("Retry-After", "60")})
            
        try:
            return JSONResponse(pr.json() if pr.text else {}, pr.status_code)
        except Exception:
            return JSONResponse({"detail": pr.text}, pr.status_code)
            
    except Exception as e:
        logger.error(f"Bridge Fail: {e}")
        raise HTTPException(500, detail="Service Unavailable")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=int(os.getenv("PROXY_PORT", 8443)), 
        reload=PROXY_DEBUG,
        ssl_certfile=os.getenv("PROXY_CERT_PATH") if os.getenv("PROXY_USE_HTTPS") == "true" else None,
        ssl_keyfile=os.getenv("PROXY_KEY_PATH") if os.getenv("PROXY_USE_HTTPS") == "true" else None
    )
