import requests
from datetime import datetime
from flask import Response, jsonify
from ._utils import get_google_access_token

def handle_generic_request(req, provider, model_config, source_label, upstream_path_suffix):
    """
    A 'Dumb' Proxy implementation mirroring colab_debugger.py.
    Forwards raw body, headers, and streams response directly.
    No prefill injection or body modification.
    """
    timestamp = datetime.now().isoformat()
    
    # 1. Base Configuration
    base_url = provider.get("base_url", "").rstrip("/")
    target_url = f"{base_url}{upstream_path_suffix}"
    
    print(f"\n[{timestamp}] 🚀 GENERIC HANDLER (RAW PROXY) ENGAGED")
    print(f"   Provider: {provider.get('name')} | Model: {model_config.get('id')}")
    print(f"   Target: {target_url}")

    # 2. Prepare Headers (Mirroring debugger.py logic + Auth)
    # Filter headers to avoid conflicts
    # debugger.py: headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length']}
    headers = {k: v for k, v in req.headers.items() if k.lower() not in ['host', 'content-length']}
    
    # Inject Provider Auth
    p_key = provider.get('api_key', '')
    if p_key == "AUTO":
         token = get_google_access_token()
         if token: p_key = token
    headers["Authorization"] = f"Bearer {p_key}"
    
    # Ensure User-Agent is clean
    headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"

    # 3. Forward to Upstream
    try:
        # We pass req.get_data() directly (Raw Bytes)
        # This avoids any JSON parsing errors or 500s from malformed bodies
        
        should_stream = True
        # Try to peek at stream setting from query params or header if body is opaque
        # But mostly we just default to stream=True for the request to upstream
        
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

        # 4. Create Response Headers (Mirroring debugger.py)
        excluded_resp_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        # Safe access to headers
        resp_headers = [(name, value) for (name, value) in resp.headers.items()
                   if name.lower() not in excluded_resp_headers]
        
        # Add Debug Headers
        resp_headers.append(("X-FunTime-Provider", provider.get("name")))
        resp_headers.append(("X-FunTime-Model", model_config.get("id")))
        resp_headers.append(("Access-Control-Allow-Origin", "*"))
        resp_headers.append(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        resp_headers.append(("Access-Control-Allow-Headers", "Content-Type, Authorization"))

        # 5. Handle Response
        # Check if it is actually an event stream
        content_type = resp.headers.get('content-type', '')
        is_stream = 'text/event-stream' in content_type

        if is_stream:
            def generate():
                # debugger.py uses chunk_size=4096. 
                # We use None to ensure Vercel doesn't buffer, but logically it's the same loop.
                try:
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
        return jsonify({"error": f"Generic Proxy Error: {str(e)}"}), 500