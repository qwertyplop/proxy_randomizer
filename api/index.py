from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import requests
import os
import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================================ 
# ⚙️ CONFIGURATION
# ============================================================================ 

ENABLE_LOGGING = os.getenv("ENABLE_LOGGING", "true").lower() == "true"

# Remote Config
CONFIG_URL = os.getenv("CONFIG_URL", "")
CONFIG_PASSWORD = os.getenv("CONFIG_PASSWORD", "")

# Prefill Content
JANITORAI_PREFILL_CONTENT = os.getenv("JANITORAI_PREFILL_CONTENT", "((OOC: Sure, let's proceed!))")
_DEFAULT_SYSTEM_CONTENT = "You are a helpful assistant."
JANITORAI_SYSTEM_PREFILL_CONTENT = os.getenv("JANITORAI_SYSTEM_PREFILL_CONTENT", _DEFAULT_SYSTEM_CONTENT)

# Caching
_CONFIG_CACHE = None
_CONFIG_CACHE_EXPIRY = datetime.min

app = Flask(__name__)
CORS(app)

def get_decryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_providers():
    """Loads providers from encrypted remote URL or local file."""
    global _CONFIG_CACHE, _CONFIG_CACHE_EXPIRY

    if _CONFIG_CACHE and datetime.now() < _CONFIG_CACHE_EXPIRY:
        return _CONFIG_CACHE

    if CONFIG_URL and CONFIG_PASSWORD:
        try:
            print(f"⬇️ Fetching config from {CONFIG_URL}...")
            # Add User-Agent to avoid being blocked by file hosts
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            resp = requests.get(CONFIG_URL, headers=headers, timeout=10)
            resp.raise_for_status()
            content = resp.content
            
            salt = content[:16]
            encrypted_data = content[16:]
            
            key = get_decryption_key(CONFIG_PASSWORD, salt)
            f = Fernet(key)
            decrypted_json = f.decrypt(encrypted_data)
            
            providers = json.loads(decrypted_json)
            
            _CONFIG_CACHE = providers
            _CONFIG_CACHE_EXPIRY = datetime.now() + timedelta(minutes=5)
            
            print("✅ Remote config loaded and decrypted successfully.")
            return providers
            
        except Exception as e:
            print(f"❌ Failed to load remote config: {e}")

    try:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_path, "providers.json")
        if not os.path.exists(config_path):
            config_path = os.path.join(os.getcwd(), "providers.json")

        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Local config not found/error: {e}")
        return []

def select_random_provider(providers):
    choices = []
    for provider in providers:
        if "models" in provider:
            for model in provider["models"]:
                choices.append((provider, model))
    if not choices: return None, None
    return random.choice(choices)

def proxy_request(source_label, upstream_path_suffix):
    timestamp = datetime.now().isoformat()
    
    providers = load_providers()
    provider, model_config = select_random_provider(providers)
    
    if not provider or not model_config:
        return jsonify({"error": "Configuration Error: No providers available (Decryption failed or empty list)."}), 500

    base_url = provider.get("base_url", "").rstrip("/")
    target_url = f"{base_url}{upstream_path_suffix}"
    
    # DEBUG LOGGING
    print(f"\n[{timestamp}] 🚀 ATTEMPTING REQUEST")
    print(f"   Source: {source_label}")
    print(f"   Provider: {provider.get('name')}")
    print(f"   Base URL (Config): {base_url}")
    print(f"   Target URL (Final): {target_url}")

    excluded_headers = ["content-length", "host", "origin", "referer", "cookie", "user-agent", "x-forwarded-for", "x-forwarded-host", "accept-encoding", "authorization"]
    clean_headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    clean_headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"
    clean_headers["Authorization"] = f"Bearer {provider.get('api_key', '')}"

    json_body = None
    data_body = None
    should_stream = True

    if request.is_json:
        try:
            incoming_body = request.get_json()
            should_stream = incoming_body.get("stream", True)
            
            json_body = {
                "messages": incoming_body.get("messages", []),
                "stream": should_stream
            }
            
            json_body["model"] = model_config.get("id")
            
            if "settings" in model_config:
                for k, v in model_config["settings"].items():
                    json_body[k] = v
            
            if source_label == "janitorai" and isinstance(json_body["messages"], list):
                enable_prefill = model_config.get("enable_prefill", False)
                if enable_prefill:
                    # Inject System Prompt at the end (Override)
                    json_body["messages"].append({"role": "system", "content": JANITORAI_SYSTEM_PREFILL_CONTENT})
                    
                    # Prepare Assistant Prefill
                    ass_msg = {"role": "assistant", "content": JANITORAI_PREFILL_CONTENT}
                    
                    # Mistral Specific: Requires 'prefix': True if the last message is Assistant
                    is_mistral = "mistral" in provider.get("base_url", "") or "mistral" in model_config.get("id", "")
                    if is_mistral:
                        ass_msg["prefix"] = True
                        
                    json_body["messages"].append(ass_msg)

        except Exception as e:
            print(f"⚠️ Error constructing body: {e}")
            json_body = request.get_json()
    else:
        data_body = request.get_data()

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=clean_headers,
            json=json_body,
            data=data_body,
            stream=should_stream,
            timeout=60
        )
        
        print(f"   ✅ Response Status: {resp.status_code}")
        
        excluded_resp_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_resp_headers]
        
        headers.append(("X-FunTime-Provider", provider.get("name")))
        headers.append(("X-FunTime-Model", model_config.get("id")))
        headers.append(("X-FunTime-Target", target_url)) # DEBUG HEADER

        if should_stream:
            def generate():
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk: yield chunk
            return Response(stream_with_context(generate()), resp.status_code, headers)
        else:
            return Response(resp.content, resp.status_code, headers)

    except Exception as e:
        print(f"   ❌ Connection Error: {e}")
        return jsonify({"error": f"Proxy Connection Failed: {str(e)}"}), 500

@app.route("/janitorai", methods=["POST", "OPTIONS"])
def janitor_proxy():
    if request.method == "OPTIONS": return "", 200
    return proxy_request("janitorai", "/chat/completions")

@app.route("/sillytavern", methods=["POST", "OPTIONS"])
def sillytavern_proxy():
    if request.method == "OPTIONS": return "", 200
    return proxy_request("sillytavern", "/chat/completions")

@app.route("/sillytavern/chat/completions", methods=["POST", "OPTIONS"])
def sillytavern_chat_proxy():
    if request.method == "OPTIONS": return "", 200
    return proxy_request("sillytavern", "/chat/completions")

@app.route("/sillytavern/models", methods=["GET", "OPTIONS"])
def sillytavern_models_proxy():
    if request.method == "OPTIONS": return "", 200
    
    return jsonify({
        "object": "list",
        "data": [
            {
                "id": "Secret",
                "object": "model",
                "created": 1677610602,
                "owned_by": "fun-time-router"
            }
        ]
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "mode": "FunTimeRouter (Encrypted)"}), 200

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "FunTimeRouter Active",
        "usage": "Configure CONFIG_URL and CONFIG_PASSWORD in Vercel."
    }), 200
    
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def catch_all(path):
    print(f"⚠️ Catch-All hit: {path}")
    return jsonify({"error": f"Catch-All: Route not found: {path}", "method": request.method}), 404

