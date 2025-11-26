from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import os

# Import Modules
# Try specific import strategies for Vercel vs Local
try:
    from ._config import (
        ENABLE_LOGGING, CONFIG_URL, CONFIG_PASSWORD, ADMIN_PASSWORD, 
        load_providers, select_random_provider
    )
    from ._utils import get_google_access_token
    from ._vertex import handle_vertex_request
    from ._generic import handle_generic_request
except ImportError:
    # Fallback for when running directly in api/ directory
    from _config import (
        ENABLE_LOGGING, CONFIG_URL, CONFIG_PASSWORD, ADMIN_PASSWORD, 
        load_providers, select_random_provider
    )
    from _utils import get_google_access_token
    from _vertex import handle_vertex_request
    from _generic import handle_generic_request

app = Flask(__name__)
CORS(app)

@app.route("/janitorai", methods=["POST", "OPTIONS"])
def janitor_proxy():
    if request.method == "OPTIONS":
        return Response(status=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        })
    return proxy_dispatcher("janitorai", "/chat/completions")

@app.route("/sillytavern", methods=["POST", "OPTIONS"])
def sillytavern_proxy():
    if request.method == "OPTIONS":
        return Response(status=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        })
    return proxy_dispatcher("sillytavern", "/chat/completions")

@app.route("/sillytavern/chat/completions", methods=["POST", "OPTIONS"])
def sillytavern_chat_proxy():
    if request.method == "OPTIONS":
        return Response(status=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        })
    return proxy_dispatcher("sillytavern", "/chat/completions")

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

def proxy_dispatcher(source_label, upstream_path_suffix):
    # 1. Load Providers
    providers = load_providers()
    
    # 2. Parse Request
    requested_model_id = None
    if request.is_json:
        try:
            body = request.get_json()
            requested_model_id = body.get("model")
        except: pass

    # 3. Admin Bypass
    incoming_key = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    provider = None
    model_config = None

    if ADMIN_PASSWORD and incoming_key == ADMIN_PASSWORD and requested_model_id:
        print(f"🔒 Admin Access: Seeking model '{requested_model_id}'")
        for p in providers:
            if "models" in p:
                for m in p["models"]:
                    if m["id"] == requested_model_id:
                        provider = p
                        model_config = m
                        break
            if provider: break

    # 4. Random Selection
    if not provider or not model_config:
        provider, model_config = select_random_provider(providers)
    
    if not provider or not model_config:
        return jsonify({"error": "Configuration Error: No providers available."}), 500

    base_url = provider.get("base_url", "")
    provider_name = provider.get("name", "").lower()
    
    # 5. Routing Logic

    # Vertex Detection
    is_vertex = ("vertex" in provider_name or "googleapis.com" in base_url) and "/openapi" not in base_url
    
    if is_vertex:
        return handle_vertex_request(request, provider, model_config, source_label)
    
    # Generic Handler (Everything else)
    return handle_generic_request(request, provider, model_config, source_label, upstream_path_suffix)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "mode": "FunTimeRouter (Modular)"}), 200

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
