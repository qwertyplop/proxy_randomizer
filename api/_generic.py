import requests
from datetime import datetime
from flask import Response, jsonify
from ._utils import get_google_access_token

def handle_generic_request(req, provider, model_config, source_label, upstream_path_suffix):
    """
    A 'Dumb' Proxy implementation mirroring colab_debugger.py.
    Forwards raw body, headers, and streams response directly.
    """
    timestamp = datetime.now().isoformat()
    
    # 1. Base Configuration
    base_url = provider.get("base_url", "").rstrip("/")
    target_url = f"{base_url}{upstream_path_suffix}"
    
    print(f"\n[{timestamp}] 🚀 GENERIC HANDLER (RAW PROXY) ENGAGED")
    print(f"   Provider: {provider.get('name')} | Model: {model_config.get('id')}")
    print(f"   Target: {target_url}")

    # Helper for CORS Headers
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "X-FunTime-Provider": provider.get("name"),
        "X-FunTime-Model": model_config.get("id")
    }

    try:
        # 2. Prepare Headers
        # Blacklist potentially problematic headers
        blacklist_headers = [
            'host', 'content-length', 'connection', 'upgrade', 'accept-encoding', 
            'transfer-encoding', 'keep-alive'
        ]
        
        headers = {}
        for k, v in req.headers.items():
            if k.lower() not in blacklist_headers:
                headers[k] = v
        
        # Inject Provider Auth
        p_key = provider.get('api_key', '')
        if p_key == "AUTO":
             token = get_google_access_token()
             if token: p_key = token
        headers["Authorization"] = f"Bearer {p_key}"
        
        # Override User-Agent
        headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"

        # 3. Forward to Upstream
        # Pass raw bytes (req.get_data()) to avoid parsing issues
        
        print(f"   Sending Request... (Stream=True)")
        
        resp = requests.request(
            method=req.method,
            url=target_url,
            headers=headers,
            data=req.get_data(), 
            cookies=req.cookies,
            allow_redirects=False,
            stream=True,
            timeout=60
        )

        print(f"   ✅ Upstream Status: {resp.status_code}")

        # 4. Create Response Headers
        excluded_resp_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = {}
        for k, v in resp.headers.items():
            if k.lower() not in excluded_resp_headers:
                resp_headers[k] = v
        
        # Merge CORS headers
        resp_headers.update(cors_headers)
        
        # Buffering Control
        resp_headers["Cache-Control"] = "no-cache"
        resp_headers["X-Accel-Buffering"] = "no"

        # 5. Handle Response
        # Check if it is actually an event stream
        content_type = resp.headers.get('content-type', '')
        is_stream = 'text/event-stream' in content_type

        if is_stream:
            def generate():
                try:
                    # chunk_size=None ensures data is yielded as soon as it arrives
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                except Exception as e:
                    print(f"Stream Error: {e}")

            return Response(generate(), resp.status_code, resp_headers)
        else:
            # Full read
            content = resp.content
            return Response(content, resp.status_code, resp_headers)

    except Exception as e:
        print(f"   ❌ Generic Request Failed: {e}")
        # Return Error with CORS headers so browser sees it
        return jsonify({"error": f"Generic Proxy Error: {str(e)}"}), 500, cors_headers
