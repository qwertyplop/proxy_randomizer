import json
import requests
from datetime import datetime
from flask import Response, jsonify
from ._utils import get_google_access_token
from ._config import (
    JANITORAI_PREFILL_CONTENT, JANITORAI_SYSTEM_PREFILL_CONTENT,
    GLM_SYSTEM_PREFILL_CONTENT, GEMINI_PREFILL_CONTENT,
    GEMINI_PREFILL_ADDITIONAL_CONTENT, MAGISTRAL_SYSTEM_PREFILL_CONTENT
)

def handle_generic_request(req, provider, model_config, source_label, upstream_path_suffix):
    timestamp = datetime.now().isoformat()
    
    # 1. Base Configuration
    base_url = provider.get("base_url", "").rstrip("/")
    target_url = f"{base_url}{upstream_path_suffix}"
    
    print(f"\n[{timestamp}] 🚀 GENERIC HANDLER ENGAGED")
    print(f"   Source: {source_label}")
    print(f"   Provider: {provider.get('name')} | Model: {model_config.get('id')}")
    print(f"   Target: {target_url}")

    # 2. Prepare Headers
    # Filter headers like debugger.py but keep Authorization logic
    excluded_headers = ['host', 'content-length', 'content-encoding', 'connection', 'transfer-encoding']
    clean_headers = {k: v for k, v in req.headers.items() if k.lower() not in excluded_headers}
    
    clean_headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"
    
    # Auth Logic
    p_key = provider.get('api_key', '')
    if p_key == "AUTO":
         token = get_google_access_token()
         if token: p_key = token
    clean_headers["Authorization"] = f"Bearer {p_key}"

    # 3. Prepare Body & Logic Injection
    json_body = None
    data_body = None
    should_stream = True
    
    if req.is_json:
        try:
            json_body = req.get_json()
            should_stream = json_body.get("stream", True)
            
            # Update Model ID
            json_body["model"] = model_config.get("id")
            
            # Apply 'settings' from config
            if "settings" in model_config:
                for k, v in model_config["settings"].items():
                    json_body[k] = v
            
            # Terminus Thinking
            if "terminus" in model_config.get("id", "").lower():
                json_body["chat_template_kwargs"] = {"thinking": True}
                
            # JanitorAI Prefill Logic
            if source_label == "janitorai" and isinstance(json_body.get("messages"), list):
                enable_prefill = model_config.get("enable_prefill", False)
                if enable_prefill:
                    model_id_lower = model_config.get("id", "").lower()
                    
                    # System Prompt Injection
                    system_content = JANITORAI_SYSTEM_PREFILL_CONTENT
                    if "glm-4" in model_id_lower and "4.5" not in model_id_lower:
                        system_content = GLM_SYSTEM_PREFILL_CONTENT
                    elif "magistral" in model_id_lower:
                        try:
                            system_content = json.loads(MAGISTRAL_SYSTEM_PREFILL_CONTENT)
                        except:
                            system_content = MAGISTRAL_SYSTEM_PREFILL_CONTENT
                    
                    if isinstance(system_content, dict):
                         json_body["messages"].append(system_content)
                    else:
                         json_body["messages"].append({"role": "system", "content": system_content})

                    # Assistant Prefill Injection
                    prefill_text = JANITORAI_PREFILL_CONTENT
                    if "gemini" in model_id_lower:
                        prefill_text = GEMINI_PREFILL_CONTENT
                    
                    ass_msg = {"role": "assistant", "content": prefill_text}
                    
                    if "mistral" in provider.get("base_url", "") or "mistral" in model_id_lower:
                        ass_msg["prefix"] = True
                    
                    json_body["messages"].append(ass_msg)
                    
                    if "gemini" in model_id_lower:
                        json_body["messages"].append({"role": "assistant", "content": GEMINI_PREFILL_ADDITIONAL_CONTENT})

        except Exception as e:
            print(f"⚠️ JSON Parse/Modify Error: {e}")
            data_body = req.get_data()
            json_body = None
    else:
        data_body = req.get_data()

    # 4. Execute Request
    try:
        resp = requests.request(
            method=req.method,
            url=target_url,
            headers=clean_headers,
            json=json_body,
            data=data_body,
            stream=should_stream,
            timeout=60,
            allow_redirects=False
        )
        
        print(f"   ✅ Upstream Status: {resp.status_code}")
        
        # 5. Prepare Response Headers
        excluded_resp_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_resp_headers]
        
        # Add Custom Headers
        headers.append(("X-FunTime-Provider", provider.get("name")))
        headers.append(("X-FunTime-Model", model_config.get("id")))
        
        # Explicit CORS & Buffering Control
        headers.append(("Access-Control-Allow-Origin", "*"))
        headers.append(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        headers.append(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        headers.append(("Cache-Control", "no-cache"))
        headers.append(("X-Accel-Buffering", "no"))

        # 6. Stream Back
        if should_stream:
            def generate():
                # Use iter_content with None to stream as fast as possible (byte-by-byte or chunk-by-chunk) 
                # mimicking the direct pass-through behavior.
                try:
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                except Exception as e:
                    print(f"Stream generation error: {e}")

            return Response(generate(), resp.status_code, headers, mimetype='text/event-stream')
        else:
            return Response(resp.content, resp.status_code, headers, mimetype='application/json')

    except Exception as e:
        print(f"   ❌ Generic Request Failed: {e}")
        return jsonify({"error": f"Generic Proxy Error: {str(e)}"}), 500
