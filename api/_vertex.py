import json
import requests
import random
from datetime import datetime
from flask import jsonify, Response
from ._utils import get_google_access_token
from ._config import GOOGLE_SA_JSON

def convert_openai_to_vertex(openai_body, model_id):
    """
    Converts OpenAI Chat Completion body to Vertex AI generateContent body.
    """
    vertex_body = {
        "contents": [],
        "generationConfig": {
            "maxOutputTokens": openai_body.get("max_tokens", 8192),
            "temperature": openai_body.get("temperature", 1.0),
            "topP": openai_body.get("top_p", 0.95),
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF"}
        ]
    }

    # Thinking Config (if requested or enabled by default for specific models)
    if "thinking" in model_id.lower() or "gemini-3" in model_id.lower() or "2.5" in model_id.lower():
        print(f"🧠 Enabling Thinking Config for {model_id}")
        t_config = {"includeThoughts": True}
        
        # User requested: Budget for 2.5, Level for 3
        if "2.5" in model_id:
            t_config["thinkingBudget"] = 24576
        elif "gemini-3" in model_id:
            t_config["thinkingLevel"] = "HIGH"
        else:
            t_config["thinkingLevel"] = "HIGH"
            
        vertex_body["generationConfig"]["thinkingConfig"] = t_config

    system_prompt_text = "" 
    
    for msg in openai_body.get("messages", []):
        role = msg.get("role")
        content = msg.get("content", "")
        
        if role == "system":
            system_prompt_text += content + "\n\n"
        elif role == "user":
            vertex_body["contents"].append({"role": "user", "parts": [{"text": content}]})
        elif role == "assistant":
            vertex_body["contents"].append({"role": "model", "parts": [{"text": content}]})
            
    # Ensure conversation starts with 'user' role and inject system prompt
    if vertex_body["contents"]:
        if vertex_body["contents"][0]["role"] == "model":
            initial_text = (system_prompt_text + "[Conversation Started]").strip()
            vertex_body["contents"].insert(0, {"role": "user", "parts": [{"text": initial_text}]})
        else:
            if system_prompt_text:
                original_text = vertex_body["contents"][0]["parts"][0]["text"]
                vertex_body["contents"][0]["parts"][0]["text"] = system_prompt_text + original_text
    else:
        if system_prompt_text:
             vertex_body["contents"].append({"role": "user", "parts": [{"text": system_prompt_text}]})
        
    return vertex_body

def stream_vertex_translation(upstream_response, source_label="", model_id=""):
    """
    Translates Vertex AI's JSON stream (array of objects) to OpenAI SSE format.
    """
    # Kimi/Qwen on Vertex seem to use a different reasoning field
    # We only want to transform this for JanitorAI, SillyTavern handles it.
    is_reasoning_model_janitor = (
        "kimi" in model_id or "qwen" in model_id
    ) and source_label == "janitorai"

    def make_sse(content):
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    if upstream_response.status_code != 200:
        try:
            err_content = upstream_response.content.decode("utf-8", errors="ignore")
            yield make_sse(f"\n\n**Vertex AI Error {upstream_response.status_code}:**\n{err_content}")
        except:
            yield make_sse(f"\n\n**Vertex AI Error {upstream_response.status_code}**")
        return

    decoder = json.JSONDecoder()
    buffer = b""
    is_thinking = False 
    first_chunk = True
    
    role_data = {
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant", "content": ""},
            "finish_reason": None
        }]
    }
    yield f"data: {json.dumps(role_data)}\n\n".encode("utf-8")
    
    try:
        print("⚡ Starting Vertex Stream Processing...", flush=True)
        for chunk in upstream_response.iter_content(chunk_size=None):
            if not chunk: continue
            
            # DEBUG LOGGING
            print(f"📝 [DEBUG] Vertex Stream Raw Chunk: {chunk}", flush=True)
            
            if first_chunk:
                print(f"🔍 Vertex Raw Stream Start: {chunk[:500]}", flush=True)
                first_chunk = False
            
            buffer += chunk
            
            while True:
                try:
                    buffer_str = buffer.decode("utf-8")
                except UnicodeDecodeError:
                    break
                
                start_idx = buffer_str.find("{")
                
                if start_idx == -1:
                    if "]" in buffer_str:
                         buffer = b""
                         break
                    if not buffer_str.strip().strip(",").strip("["):
                        buffer = b""
                    break
                
                potential_json = buffer_str[start_idx:]
                
                try:
                    obj, idx = decoder.raw_decode(potential_json)
                    total_consumed = start_idx + idx
                    
                    print(f"✅ Parsed Object. Consumed: {total_consumed} chars", flush=True)
                    
                    if is_reasoning_model_janitor:
                        # Handle Kimi/Qwen/etc reasoning_content for JanitorAI
                        reasoning = obj.get("reasoning_content", "")
                        if reasoning:
                             if not is_thinking:
                                 yield make_sse("<think>")
                                 is_thinking = True
                             yield make_sse(reasoning)

                        content = obj.get("content", "")
                        if content:
                            if is_thinking:
                                yield make_sse("</think>")
                                is_thinking = False
                            yield make_sse(content)
                    else:
                        # Standard Vertex `thought` field handling
                        candidates = obj.get("candidates", [])
                        if candidates:
                            cand = candidates[0]
                            parts = cand.get("content", {}).get("parts", [])
                            
                            for part in parts:
                                text = part.get("text", "")
                                is_thought_part = part.get("thought", False)
                                
                                if is_thought_part:
                                    if not is_thinking:
                                        yield make_sse("<think>\n")
                                        is_thinking = True
                                    yield make_sse(text)
                                else:
                                    if is_thinking:
                                        yield make_sse("\n</think>\n")
                                        is_thinking = False
                                    yield make_sse(text)
                                
                    if "error" in obj:
                         err_msg = json.dumps(obj["error"])
                         yield make_sse(f"\n\n**Vertex Stream Error:** {err_msg}")

                    remaining_str = buffer_str[total_consumed:]
                    buffer = remaining_str.encode("utf-8")
                    
                except json.JSONDecodeError:
                    break
                
        if is_thinking:
             yield make_sse("\n</think>\n")
        
        final_data = {
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        }
        yield f"data: {json.dumps(final_data)}\n\n".encode("utf-8")
             
        yield "data: [DONE]\n\n".encode("utf-8")
                        
    except Exception as e:
        print(f"Vertex Stream Error: {e}", flush=True)
        yield make_sse(f"\n\n**Proxy Stream Exception:** {str(e)}")
        yield "data: [DONE]\n\n".encode("utf-8")

def translate_vertex_non_stream(raw_content, source_label="", model_id=""):
    """
    Translates a full Vertex AI response JSON to OpenAI Chat Completion JSON.
    """
    try:
        # DEBUG LOGGING
        print(f"📝 [DEBUG] Vertex Raw Response: {raw_content.decode('utf-8', errors='ignore')}", flush=True)
        
        data = json.loads(raw_content)

        is_reasoning_model_janitor = (
            "kimi" in model_id or "qwen" in model_id
        ) and source_label == "janitorai"

        if is_reasoning_model_janitor:
            # Handle Kimi/Qwen non-streaming for JanitorAI
            reasoning = data.get("reasoning_content", "")
            content = data.get("content", "")
            if reasoning:
                full_text = f"<think>{reasoning}</think>\n{content}"
            else:
                full_text = content
        else:
            # Standard Vertex non-streaming
            full_text = ""
            candidates = data.get("candidates", [])
            if candidates:
                cand = candidates[0]
                parts = cand.get("content", {}).get("parts", [])
                
                is_thinking = False
                for part in parts:
                    text = part.get("text", "")
                    is_thought_part = part.get("thought", False)
                    
                    if is_thought_part:
                        if not is_thinking:
                            full_text += "<think>\n"
                            is_thinking = True
                        full_text += text
                    else:
                        if is_thinking:
                            full_text += "\n</think>\n"
                            is_thinking = False
                        full_text += text
                
                if is_thinking:
                    full_text += "\n</think>\n"
        
        openai_resp = {
            "id": "chatcmpl-vertex-" + str(random.randint(100000, 999999)),
            "object": "chat.completion",
            "created": int(datetime.now().timestamp()),
            "model": "vertex-gemini", 
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": full_text
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        }
        return json.dumps(openai_resp).encode("utf-8")
        
    except Exception as e:
        print(f"❌ Vertex Non-Stream Translation Error: {e}")
        return raw_content

def handle_vertex_request(req, provider, model_config, source_label=""):
    """
    Specialized handler for Vertex AI that strictly mimics the working Colab debugger logic.
    """
    timestamp = datetime.now().isoformat()
    print(f"\n[{timestamp}] ⚡ VERTEX HANDLER ENGAGED")
    
    try:
        req_body = req.get_json(force=True)
        is_stream = req_body.get("stream", True)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    token = get_google_access_token()
    if not token:
        return jsonify({"error": "Failed to generate Google Token. Check JSON config."}), 500

    model_id = model_config.get("id")
    vertex_body = convert_openai_to_vertex(req_body, model_id)
    
    project_id = ""
    location = "global" 
    
    if GOOGLE_SA_JSON:
        try:
            sa_info = json.loads(GOOGLE_SA_JSON)
            project_id = sa_info.get("project_id")
        except: pass
        
    base_url = provider.get("base_url", "")
    if "global" in base_url: location = "global"
    elif "us-central1" in base_url: location = "us-central1"
    elif "europe-west1" in base_url: location = "europe-west1"
    elif "us-west1" in base_url: location = "us-west1"
    
    if location == 'global':
        host = "aiplatform.googleapis.com"
    else:
        host = f"{location}-aiplatform.googleapis.com"
        
    if is_stream:
        url = f"https://{host}/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model_id}:streamGenerateContent?alt=sse"
    else:
        url = f"https://{host}/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model_id}:generateContent"
    
    print(f"   Target URL: {url}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        if is_stream:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=True, timeout=60)
            
            response_headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Content-Type": "text/event-stream"
            }
            
            return Response(
                stream_vertex_translation(resp, source_label, model_id),
                status=resp.status_code,
                headers=response_headers
            )
        else:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=False, timeout=60)
            
            translated = translate_vertex_non_stream(resp.content, source_label, model_id)
            
            response_headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Content-Type": "application/json"
            }
            
            return Response(translated, status=resp.status_code, headers=response_headers)

    except Exception as e:
        print(f"Vertex Request Failed: {e}", flush=True)
        return jsonify({"error": f"Vertex Request Failed: {e}"}), 500
