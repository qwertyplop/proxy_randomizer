import json
import requests
import random
from datetime import datetime
from flask import Response, jsonify, stream_with_context
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
    
    print(f"\n[{timestamp}] 🚀 GENERIC HANDLER (REFERENCE BASED) ENGAGED")
    print(f"   Source: {source_label}")
    print(f"   Provider: {provider.get('name')} | Model: {model_config.get('id')}")
    print(f"   Target: {target_url}")

    # 2. Prepare Headers
    excluded_headers = ['content-length', 'host', 'origin', 'referer', 'cookie', 'user-agent', 'x-forwarded-for', 'x-forwarded-host', 'accept-encoding', 'connection', 'upgrade']
    
    clean_headers = {
        k: v for k, v in req.headers.items() 
        if k.lower() not in excluded_headers
    }
    
    clean_headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"

    # Auth Logic
    p_key_config = provider.get('api_key', '')
    
    if isinstance(p_key_config, list) and p_key_config:
        p_key = random.choice(p_key_config)
    else:
        p_key = p_key_config

    if p_key == "AUTO":
         token = get_google_access_token()
         if token: p_key = token
    clean_headers["Authorization"] = f"Bearer {p_key}"

    # 3. Body Handling & Injection
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

            # Client-Specific Prefill (JanitorAI)
            if source_label == "janitorai" and "messages" in json_body and isinstance(json_body["messages"], list):
                model_id_lower = model_config.get("id", "").lower()
                enable_prefill = model_config.get("enable_prefill", False)

                # ALWAYS inject Magistral template for JanitorAI, regardless of prefill setting
                if "magistral" in model_id_lower:
                     print("   💉 Injecting Magistral Template (Mandatory)")
                     try:
                         mag_content = json.loads(MAGISTRAL_SYSTEM_PREFILL_CONTENT)
                         json_body["messages"].append(mag_content)
                     except:
                         json_body["messages"].append({"role": "system", "content": MAGISTRAL_SYSTEM_PREFILL_CONTENT})

                # Handle other prefills (controlled by setting)
                if enable_prefill:
                    # 1. Determine System Content (Skip if Magistral, already handled)
                    if "magistral" not in model_id_lower:
                        system_content = JANITORAI_SYSTEM_PREFILL_CONTENT
                        if "glm-4" in model_id_lower and "4.5" not in model_id_lower:
                            system_content = GLM_SYSTEM_PREFILL_CONTENT

                        # 2. Inject System Message
                        print("   💉 Injecting System Prefill")
                        if isinstance(system_content, dict):
                             json_body["messages"].append(system_content)
                        else:
                             json_body["messages"].append({"role": "system", "content": system_content})

                    # 3. Determine Assistant Prefill
                    prefill_text = JANITORAI_PREFILL_CONTENT
                    if "gemini" in model_id_lower:
                        prefill_text = GEMINI_PREFILL_CONTENT
                    
                    ass_msg = {"role": "assistant", "content": prefill_text}
                    
                    if "mistral" in provider.get("base_url", "") or "mistral" in model_id_lower:
                        ass_msg["prefix"] = True
                    
                    # 4. Inject Assistant Prefill
                    print("   💉 Injecting Assistant Prefill")
                    json_body["messages"].append(ass_msg)
                    
                    if "gemini" in model_id_lower:
                        json_body["messages"].append({"role": "assistant", "content": GEMINI_PREFILL_ADDITIONAL_CONTENT})

        except Exception as e:
            print(f"⚠️ Failed to process/inject body: {e}")
            json_body = req.get_json() # Fallback to original
    else:
        data_body = req.get_data()

    # 4. Forward Request
    try:
        # DEBUG LOGGING: Request Body
        if json_body:
            print(f"📝 [DEBUG] Outgoing Request Body:\n{json.dumps(json_body, indent=2)}")
        elif data_body:
            print(f"📝 [DEBUG] Outgoing Request Data: {data_body[:500]}...")

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
        
        # 5. Response Headers
        excluded_resp_headers = [
            'content-encoding', 'content-length', 'transfer-encoding', 'connection',
            'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers'
        ]
        resp_headers = [
            (name, value) for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_resp_headers
        ]
        
        # Add CORS & Debug Headers
        resp_headers.append(("X-FunTime-Provider", provider.get("name")))
        resp_headers.append(("X-FunTime-Model", model_config.get("id")))
        resp_headers.append(("Access-Control-Allow-Origin", "*"))
        resp_headers.append(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        resp_headers.append(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        resp_headers.append(("Cache-Control", "no-cache"))
        resp_headers.append(("X-Accel-Buffering", "no"))

        # Magistral Handling
        is_magistral = "magistral" in model_config.get("id", "").lower() and source_label == "janitorai"

        # 6. Stream Response
        if should_stream:
            def generate():
                if is_magistral:
                    # Magistral Streaming Logic
                    is_thinking = False

                    for line in resp.iter_lines():
                        decoded_line = line.decode('utf-8')
                        # DEBUG LOGGING: Raw Stream Line
                        if decoded_line.strip():
                             print(f"🔍 [DEBUG] Stream Line: {decoded_line}")

                        if decoded_line.startswith("data: ") and decoded_line != "data: [DONE]":
                            try:
                                json_str = decoded_line[6:]  # Remove "data: "
                                chunk = json.loads(json_str)
                                choices = chunk.get("choices", [])
                                
                                if choices:
                                    delta = choices[0].get("delta", {})
                                    content = delta.get("content")
                                    
                                    if isinstance(content, list):
                                        # Transform Structured Content in Stream (Stateful)
                                        final_text = ""
                                        for item in content:
                                            if item.get("type") == "thinking":
                                                if not is_thinking:
                                                    final_text += "<think>"
                                                    is_thinking = True
                                                
                                                think_text = ""
                                                thinking_content = item.get("thinking")
                                                if isinstance(thinking_content, list):
                                                    for t_item in thinking_content:
                                                        if t_item.get("type") == "text":
                                                            think_text += t_item.get("text", "")
                                                elif isinstance(thinking_content, str):
                                                    think_text = thinking_content
                                                
                                                final_text += think_text
                                                
                                            elif item.get("type") == "text":
                                                if is_thinking:
                                                    final_text += "</think>"
                                                    is_thinking = False
                                                final_text += item.get("text", "")
                                        
                                        # Update chunk
                                        chunk["choices"][0]["delta"]["content"] = final_text
                                        new_line = "data: " + json.dumps(chunk)
                                        yield new_line + "\n"
                                    else:
                                        yield decoded_line + "\n"
                                else:
                                    yield decoded_line + "\n"
                            except Exception as e:
                                print(f"⚠️ Stream Parse Error: {e}")
                                yield decoded_line + "\n"
                        elif decoded_line == "data: [DONE]":
                            if is_thinking:
                                # Close thinking tag if stream ends
                                final_chunk = {
                                    "choices": [{
                                        "index": 0,
                                        "delta": {"content": "</think>"},
                                        "finish_reason": None
                                    }]
                                }
                                yield "data: " + json.dumps(final_chunk) + "\n"
                                is_thinking = False
                            yield decoded_line + "\n"
                        else:
                            yield decoded_line + "\n"
                else:
                    # Standard Streaming
                    for chunk in resp.iter_content(chunk_size=4096):
                        if chunk: yield chunk

            return Response(stream_with_context(generate()), resp.status_code, resp_headers)
        else:
            # Non-Streaming
            content = resp.content
            
            # DEBUG LOGGING: Raw Response
            try:
                print(f"📝 [DEBUG] Raw Upstream Response:\n{content.decode('utf-8')}")
            except:
                print(f"📝 [DEBUG] Raw Upstream Response (Binary): {len(content)} bytes")

            if is_magistral and resp.status_code == 200:
                try:
                    body = resp.json()
                    choices = body.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {})
                        inner_content = msg.get("content")
                        
                        if isinstance(inner_content, list):
                            # Transform Magistral Structured Content
                            final_text = ""
                            for item in inner_content:
                                if item.get("type") == "thinking":
                                    # Extract thinking text
                                    think_text = ""
                                    if "thinking" in item and isinstance(item["thinking"], list):
                                        for t_item in item["thinking"]:
                                            if t_item.get("type") == "text":
                                                think_text += t_item.get("text", "")
                                    elif "thinking" in item and isinstance(item["thinking"], str):
                                        think_text = item["thinking"]
                                        
                                    final_text += f"<think>{think_text}</think>\n"
                                    
                                elif item.get("type") == "text":
                                    final_text += item.get("text", "")
                            
                            # Update body
                            body["choices"][0]["message"]["content"] = final_text
                            content = json.dumps(body).encode('utf-8')
                            
                except Exception as e:
                    print(f"⚠️ Failed to transform Magistral response: {e}")
            
            return Response(content, resp.status_code, resp_headers)

    except Exception as e:
        print(f"   ❌ Generic Request Failed: {e}")
        # Return Error with CORS headers
        error_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
        return jsonify({"error": f"Generic Proxy Error: {str(e)}"}), 500, error_headers
