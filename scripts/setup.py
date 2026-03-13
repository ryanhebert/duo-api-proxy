import os
import secrets
import shutil
import subprocess
import re
import sys

# Detect project root (one level up from scripts/ directory)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
os.chdir(PROJECT_ROOT)

def load_existing_env(path=".env"):
    """Loads existing .env values to use as defaults."""
    env = {}
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env[key.strip()] = value.strip()
    return env

def validate_duo_host(host):
    return bool(re.match(r'^api-[a-f0-9]{8}\.duosecurity\.com$', host))

def validate_ikey(ikey):
    return len(ikey) == 20 and ikey.startswith("DI")

def validate_skey(skey):
    return len(skey) == 40

def setup():
    env_path = ".env"
    
    print("==================================================")
    print("      Duo Admin API Proxy Setup Utility")
    print("==================================================")

    # 0. Environment Setup
    print("\n--- 0. Python Environment ---")
    if not os.path.exists("venv"):
        create_venv = input("Create a virtual environment and install requirements? (y/n) [y]: ").lower() != 'n'
        if create_venv:
            print("Creating venv...")
            subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
            
            # Determine pip path based on OS
            pip_cmd = os.path.join("venv", "Scripts", "pip") if os.name == "nt" else os.path.join("venv", "bin", "pip")
            
            print("Installing requirements.txt...")
            try:
                subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
                print("[SUCCESS] Environment and dependencies ready.")
            except Exception as e:
                print(f"[ERROR] Failed to install requirements: {e}")
    else:
        print("Existing virtual environment (venv) detected.")

    existing = load_existing_env(env_path)
    if existing:
        print("\nExisting configuration detected. Press Enter to keep current values.")
    
    # 1. Duo Admin API Configuration
    print("\n--- 1. Duo Admin API (Backend) ---")
    
    while True:
        default = existing.get("DUO_HOST", "api-xxxxxxxx.duosecurity.com")
        duo_host = input(f"Duo API Hostname [{default}]: ").strip() or default
        if validate_duo_host(duo_host) or duo_host == default:
            break
        print("Invalid hostname format. Should be like: api-837f8f1f.duosecurity.com")

    while True:
        default = existing.get("DUO_IKEY", "")
        duo_ikey = input(f"Admin API Integration Key (ikey) [{default}]: ").strip() or default
        if validate_ikey(duo_ikey) or not duo_ikey:
            break
        print("Invalid ikey. Must be 20 characters and start with 'DI'.")

    while True:
        default = existing.get("DUO_SKEY", "")
        duo_skey = input(f"Admin API Secret Key (skey) [{default}]: ").strip() or default
        if validate_skey(duo_skey) or not duo_skey:
            break
        print("Invalid skey. Must be exactly 40 characters.")
    
    # 2. Duo SSO Configuration
    print("\n--- 2. Duo SSO / OIDC (Frontend) ---")
    sso_id_def = existing.get("DUO_SSO_CLIENT_ID", "")
    sso_client_id = input(f"OIDC Client ID [{sso_id_def}]: ").strip() or sso_id_def
    
    sso_sec_def = existing.get("DUO_SSO_CLIENT_SECRET", "")
    sso_client_secret = input(f"OIDC Client Secret [{sso_sec_def}]: ").strip() or sso_sec_def
    
    default_well_known = existing.get("DUO_SSO_WELL_KNOWN_URL", f"https://{duo_host}/oidc/v1/.well-known/openid-configuration")
    sso_well_known = input(f"SSO Well-Known URL [{default_well_known}]: ").strip() or default_well_known
    
    # 3. HTTPS Setup
    print("\n--- 3. HTTPS Setup ---")
    https_def_raw = existing.get("PROXY_USE_HTTPS", "false").lower()
    https_def_bool = https_def_raw == "true"
    
    use_https_input = input(f"Enable HTTPS with self-signed certificates? (y/n) [{'y' if https_def_bool else 'n'}]: ").lower()
    if not use_https_input:
        use_https = https_def_bool
    else:
        use_https = use_https_input == 'y'
    
    cert_path = ""
    key_path = ""
    default_port = existing.get("PROXY_PORT", "8443" if use_https else "8000")
    
    if use_https:
        cert_dir = "certs"
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        
        cert_path = os.path.join(cert_dir, "proxy.crt")
        key_path = os.path.join(cert_dir, "proxy.key")
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print("Missing or new HTTPS configuration. Generating self-signed SSL certificates...")
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                import datetime

                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Duo Admin Proxy"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
                ])
                cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                    key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
                    datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)
                ).sign(key, hashes.SHA256())

                with open(key_path, "wb") as f:
                    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
                with open(cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                print(f"Certificates created in ./{cert_dir}")
            except ImportError:
                print("[WARNING] 'cryptography' library not found. Skipping cert generation.")
                print("Please run 'pip install -r requirements.txt' first.")
    else:
        cert_path = ""
        key_path = ""

    # 4. Proxy Settings
    print("\n--- 4. Proxy Settings ---")
    proxy_port = input(f"Proxy Port [{default_port}]: ").strip() or default_port
    
    docs_def = existing.get("PROXY_ENABLE_DOCS", "true").lower() == "true"
    enable_docs = input(f"Enable Swagger UI documentation? (y/n) [{'y' if docs_def else 'n'}]: ").lower()
    if not enable_docs:
        enable_docs = docs_def
    else:
        enable_docs = enable_docs != 'n'

    spec_def = existing.get("OPENAPI_SPEC_PATH", "../duoMcp/duo-admin-api.yaml")
    openapi_path = input(f"Path to OpenAPI spec [{spec_def}]: ").strip() or spec_def
    
    ttl_def = existing.get("REVOCATION_CHECK_CACHE_SECONDS", "30")
    cache_ttl = input(f"Revocation check cache (seconds) [{ttl_def}]: ").strip() or ttl_def
    
    redis_def = existing.get("REDIS_URL", "")
    redis_url = input(f"Redis URL (optional) [{redis_def}]: ").strip() or redis_def
    
    # 5. Dynamic Client Registration (DCR)
    print("\n--- 5. Dynamic Client Registration (DCR) ---")
    dcr_def = existing.get("PROXY_ENABLE_DCR", "false").lower() == "true"
    enable_dcr = input(f"Enable Dynamic Client Registration? (y/n) [{'y' if dcr_def else 'n'}]: ").lower()
    if not enable_dcr:
        enable_dcr = dcr_def
    else:
        enable_dcr = enable_dcr == 'y'

    dcr_token = ""
    if enable_dcr:
        dcr_token_def = existing.get("DCR_INITIAL_ACCESS_TOKEN", "")
        if dcr_token_def:
            regen = input("Existing DCR token found. Regenerate it? (y/n) [n]: ").lower() == 'y'
            if regen:
                dcr_token = secrets.token_hex(32)
                print(f"  [GENERATED] New DCR_INITIAL_ACCESS_TOKEN: {dcr_token}")
            else:
                dcr_token = dcr_token_def
        else:
            auto = input("Auto-generate a secure DCR Initial Access Token? (y/n) [y]: ").lower() != 'n'
            if auto:
                dcr_token = secrets.token_hex(32)
                print(f"  [GENERATED] DCR_INITIAL_ACCESS_TOKEN: {dcr_token}")
                print("  Save this token — you will need it to register clients via the Swagger UI.")
            else:
                dcr_token = input("  Enter DCR Initial Access Token: ").strip()

    # Generate or reuse session secret
    existing_secret = existing.get("PROXY_SESSION_SECRET")
    if existing_secret:
        rotate_secret = input("\nExisting session secret found. Force logout for all users by generating a new one? (y/n) [n]: ").lower() == 'y'
        session_secret = secrets.token_hex(32) if rotate_secret else existing_secret
    else:
        session_secret = secrets.token_hex(32)

    # Summary
    print("\n==================================================")
    print("      Configuration Summary")
    print("==================================================")
    print(f"Duo Host:    {duo_host}")
    print(f"Proxy Port:  {proxy_port}")
    print(f"HTTPS:       {'Enabled' if use_https else 'Disabled'}")
    print(f"Docs UI:     {'Enabled' if enable_docs else 'Disabled'}")
    print(f"DCR:         {'Enabled (token set)' if enable_dcr and dcr_token else 'Enabled (NO TOKEN - startup will fail!)' if enable_dcr else 'Disabled'}")
    print(f"Caching:     {'Redis' if redis_url else 'In-Memory'}")
    print("==================================================")
    
    confirm = input("\nSave this configuration? (y/n) [y]: ").lower() != 'n'
    if not confirm:
        print("Setup aborted.")
        return

    env_content = f"""# =================================================================
# Duo Admin API OAuth 2.1 Proxy Configuration
# =================================================================
# NOTE: This file was generated by setup.py.
# =================================================================

# --- Duo Admin API (Backend Credentials) ---
# Found in: Duo Admin Panel -> Applications -> Admin API
DUO_HOST={duo_host}
DUO_IKEY={duo_ikey}
DUO_SKEY={duo_skey}

# --- Duo SSO / OIDC (Frontend Authentication) ---
# Found in: Duo Admin Panel -> Applications -> OAuth 2.1 / OIDC
DUO_SSO_CLIENT_ID={sso_client_id}
DUO_SSO_CLIENT_SECRET={sso_client_secret}
DUO_SSO_WELL_KNOWN_URL={sso_well_known}

# --- Proxy Security & Settings ---
# A long random string used to sign browser session cookies
PROXY_SESSION_SECRET={session_secret}
PROXY_PORT={proxy_port}

# Set to false to hide the Swagger UI and OpenAPI spec in production
PROXY_ENABLE_DOCS={'true' if enable_docs else 'false'}

# SSL Settings
PROXY_USE_HTTPS={'true' if use_https else 'false'}
PROXY_CERT_PATH={cert_path}
PROXY_KEY_PATH={key_path}

# Optional: Path to the OpenAPI YAML specification
OPENAPI_SPEC_PATH={openapi_path}

# Optional: How many seconds to cache Duo user status (Default: 30)
# This controls how often the proxy "phones home" to Duo to verify active status.
REVOCATION_CHECK_CACHE_SECONDS={cache_ttl}

# --- Distributed Caching (Optional) ---
# Required if running multiple instances. Leave blank for in-memory.
REDIS_URL={redis_url}

# --- Dynamic Client Registration (DCR) ---
# Set to true to allow clients to register themselves via POST /register
PROXY_ENABLE_DCR={'true' if enable_dcr else 'false'}
# Optional: Require this token in the 'Authorization: Bearer <token>' header to allow registration
DCR_INITIAL_ACCESS_TOKEN={dcr_token}
"""

    try:
        with open(env_path, "w") as f:
            f.write(env_content)

        print(f"\n[SUCCESS] .env file updated at: {os.path.abspath(env_path)}")

        docker_cmd = shutil.which("docker-compose") or shutil.which("docker")
        if docker_cmd:
            start_now = input("\nWould you like to start the proxy in production (Docker) now? (y/n): ")
            if start_now.lower() == 'y':
                compose_file = os.path.join("deploy", "docker-compose.yml")
                base_cmd = [docker_cmd]
                if "docker-compose" not in docker_cmd: base_cmd.append("compose")
                full_cmd = base_cmd + ["-f", compose_file, "up", "--build", "-d"]
                try:
                    subprocess.run(full_cmd, check=True)
                    proto = "https" if use_https else "http"
                    print(f"\n[DONE] Running at {proto}://localhost:{proxy_port}/docs")
                except Exception as e:
                    print(f"\n[ERROR] Docker failed: {e}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write .env file: {e}")

if __name__ == "__main__":
    setup()
