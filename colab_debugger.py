# --- CONFIGURATION ---
UPSTREAM_URL = "https://your-deployment.vercel.app"  # <--- REPLACE THIS (No trailing slash)
PORT = 5000

# --- VERTEX AI CONFIGURATION (FILL THIS IN COLAB) ---
GOOGLE_PROJECT_ID = "your-project-id"
GOOGLE_LOCATION = "us-central1"
GOOGLE_SERVICE_ACCOUNT_JSON = r"""
{
  "type": "service_account",
  ... paste your full JSON content here ...
}
"""

# --- INSTALL DEPENDENCIES ---
import subprocess
import sys
import time
import re
import threading
import os

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import flask
    import requests
    from google.oauth2 import service_account
    import google.auth.transport.requests
except ImportError:
    print("Installing dependencies...")
    install("flask")
    install("requests")
    install("google-auth")
    install("google-auth-httplib2")
    install("google-auth-oauthlib")
    import flask
    import requests
    from google.oauth2 import service_account
    import google.auth.transport.requests

from flask import Flask, request, Response
import json

app = Flask(__name__)

# --- HELPERS ---

def get_google_access_token():
    """Generates a fresh Google Access Token."""
    try:
        info = json.loads(GOOGLE_SERVICE_ACCOUNT_JSON)
        creds = service_account.Credentials.from_service_account_info(
            info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        request_adapter = google.auth.transport.requests.Request()
        creds.refresh(request_adapter)
        return creds.token
    except Exception as e:
        print(f"❌ Failed to generate Google Token: {e}")
        return None

def convert_openai_to_vertex(openai_body, model_id):
    """Converts OpenAI Chat Completion body to Vertex AI generateContent body."""
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

    if "thinking" in model_id.lower() or "gemini-3" in model_id.lower() or "2.5" in model_id.lower():
        t_config = {"includeThoughts": True}
        if "2.5" in model_id:
            t_config["thinkingBudget"] = 16384 # Lower budget for testing
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

def translate_vertex_non_stream(raw_content):
    """
    Translates a full Vertex AI response JSON to OpenAI Chat Completion JSON.
    """
    try:
        data = json.loads(raw_content)
        
        # Extract content
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
        
        # Construct OpenAI Response
        openai_resp = {
            "id": "chatcmpl-vertex-" + str(int(time.time())),
            "object": "chat.completion",
            "created": int(time.time()),
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
        return raw_content # Fallback

def stream_vertex_translation(upstream_response):
    """Translates Vertex AI's JSON stream (array of objects) to OpenAI SSE format."""
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
            print(f"❌ Vertex API Error: {err_content}")
            yield make_sse(f"\n\n**Vertex AI Error {upstream_response.status_code}:**\n{err_content}")
        except:
             pass
        return

    decoder = json.JSONDecoder()
    buffer = b""
    is_thinking = False
    
    print("⚡ Starting Vertex Stream Processing...", flush=True)
    
    try:
        for chunk in upstream_response.iter_content(chunk_size=None):
            if not chunk: continue
            
            # Log Raw Chunk (Verbose but useful)
            # print(f"Raw Chunk: {chunk[:200]}...") 
            
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
                    
                    # LOGGING: Print valid objects
                    print(f"RAW VERTEX OBJ: {json.dumps(obj)}") 

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
                                
                    remaining_str = buffer_str[total_consumed:]
                    buffer = remaining_str.encode("utf-8")
                    
                except json.JSONDecodeError:
                    break
                
        if is_thinking:
             yield make_sse("\n</think>\n")
             
        yield "data: [DONE]\n\n".encode("utf-8")
        print("\n✅ Stream Completed Successfully")
                    
    except Exception as e:
        print(f"Stream Error: {e}")
        yield make_sse(f"\n\n**Proxy Stream Exception:** {str(e)}")
        yield "data: [DONE]\n\n".encode("utf-8")

# --- ROUTES ---

def log_request(path, method, headers, body):
    print(f"\n{'='*20} INCOMING REQUEST {'='*20}")
    print(f"Path: /{path}")
    print(f"Method: {method}")
    print("Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    
    if body:
        try:
            print("Body (JSON):")
            print(json.dumps(json.loads(body), indent=2))
        except:
            print(f"Body (Raw): {body!r}") # Full body
    print(f"{ '='*58}\n")

def log_response(status_code, headers, content):
    print(f"\n{'='*20} UPSTREAM RESPONSE {'='*20}")
    print(f"Status: {status_code}")
    print("Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    
    try:
        if content:
            # Try to print as text first
            text = content.decode('utf-8', errors='replace')
            try:
                print("Body (JSON):")
                print(json.dumps(json.loads(text), indent=2))
            except:
                print(f"Body (Text): {text}")
    except:
        print(f"Body (Binary): {len(content)} bytes")
    print(f"{ '='*59}\n")

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def catch_all(path):
    # 1. Prepare Request
    # IGNORE the path from the incoming request because we are hitting a specific endpoint
    target_url = UPSTREAM_URL
    
    # Filter headers to avoid conflicts and strip identity
    excluded_headers = [
        'host', 'content-length', 'origin', 'referer', 'user-agent', 
        'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'forwarded', 'via'
    ]
    headers = {k: v for k, v in request.headers if k.lower() not in excluded_headers}
    headers["User-Agent"] = "Mozilla/5.0 (compatible; ColabProxy/1.0)"
    
    # Log Incoming
    log_request(path, request.method, headers, request.get_data())

    try:
        # 2. Forward to Upstream
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True 
        )

        # 3. Create Response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        # Read first chunk to log (if streaming) or full body if not
        # Note: True streaming logging is hard without breaking the stream. 
        # We will peek at the response if it's not a stream, or just log headers if it is.
        
        is_stream = resp.headers.get('content-type', '').startswith('text/event-stream')
        
        if is_stream:
            print(f"--- [STREAMING RESPONSE DETECTED from {target_url}] ---")
            def generate():
                full_response_log = []
                try:
                    for chunk in resp.iter_content(chunk_size=4096):
                        if chunk:
                            # Accumulate for logging
                            full_response_log.append(chunk)
                            yield chunk
                finally:
                    # Log the full accumulated body after stream ends
                    total_body = b"".join(full_response_log)
                    print(f"\n--- [FULL STREAM BODY CAPTURED] ---")
                    try:
                        print(total_body.decode('utf-8', errors='replace'))
                    except:
                         print(f"<Binary/Non-decodable data: {len(total_body)} bytes>")
                    print(f"-----------------------------------\n")

            return Response(generate(), resp.status_code, headers)
        else:
            # Full read for logging
            content = resp.content
            log_response(resp.status_code, dict(headers), content)
            return Response(content, resp.status_code, headers)

    except Exception as e:
        print(f"!!! PROXY ERROR: {e}")
        return Response(f"Proxy Error: {str(e)}", 500)

@app.route('/vertex-test', methods=['POST', 'OPTIONS'])
@app.route('/vertex-test/chat/completions', methods=['POST', 'OPTIONS'])
def vertex_test():
    """
    Real implementation of Vertex AI proxying.
    """
    print(f"\n!!! ENTERING VERTEX_TEST ROUTE !!!")
    print(f"Request: {request.method} {request.url}")

    # Standard CORS Headers
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }

    if request.method == 'OPTIONS':
         print("Handling OPTIONS request -> 200 OK with CORS")
         return Response(status=200, headers=cors_headers)

    print(f"\n{'='*20} VERTEX REQUEST TEST {'='*20}")
    
    # 1. Parse Input
    try:
        raw_data = request.get_data()
        print(f"Raw Request Body Length: {len(raw_data)} bytes")
        # print(f"Raw Request Body Preview: {raw_data[:200]}...")

        req_body = json.loads(raw_data)
        print("Input Body (OpenAI format): Parsed Successfully")
        # print(json.dumps(req_body, indent=2))
    except Exception as e:
        print(f"❌ JSON PARSING FAILED: {e}")
        print(f"Raw Data content: {request.get_data()}")
        return Response(f"Invalid JSON: {e}", 400, headers=cors_headers)

    # 2. Authenticate
    token = get_google_access_token()
    if not token:
        return Response("Failed to get Google Token. Check JSON config.", 500, headers=cors_headers)

    # 3. Translate Body
    model_id = req_body.get("model", "gemini-2.0-flash-exp") 
    vertex_body = convert_openai_to_vertex(req_body, model_id)
    
    print(f"Translated Body (Vertex format for {model_id}):")
    print(json.dumps(vertex_body, indent=2))

    # 4. Construct Request
    if GOOGLE_LOCATION == 'global':
        host = "aiplatform.googleapis.com"
    else:
        host = f"{GOOGLE_LOCATION}-aiplatform.googleapis.com"
        
    is_stream = req_body.get("stream", True)
    
    if is_stream:
        url = f"https://{host}/v1/projects/{GOOGLE_PROJECT_ID}/locations/{GOOGLE_LOCATION}/publishers/google/models/{model_id}:streamGenerateContent?alt=sse"
    else:
        url = f"https://{host}/v1/projects/{GOOGLE_PROJECT_ID}/locations/{GOOGLE_LOCATION}/publishers/google/models/{model_id}:generateContent"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # 5. Send to Vertex
    try:
        print(f"🚀 Sending to Vertex (Stream={is_stream}): {url}")
        
        if is_stream:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=True)
            return Response(
                stream_vertex_translation(resp),
                mimetype='text/event-stream',
                headers=cors_headers
            )
        else:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=False)
            print(f"Response Status: {resp.status_code}")
            
            raw_content = resp.content.decode("utf-8")
            print(f"RAW VERTEX RESPONSE:\n{raw_content}")
            
            translated = translate_vertex_non_stream(raw_content)
            print(f"TRANSLATED RESPONSE:\n{translated.decode('utf-8')}")
            
            return Response(translated, mimetype='application/json', headers=cors_headers)

    except Exception as e:
        print(f"Vertex Request Failed: {e}")
        return Response(f"Vertex Request Failed: {e}", 500, headers=cors_headers)



def start_cloudflared(port):
    """
    Downloads and starts cloudflared to create a public tunnel.
    """
    print(f"☁️  Setting up Cloudflared Tunnel on port {port}...")
    
    # Download cloudflared (Linux specific, which Colab uses)
    subprocess.run(["wget", "-q", "-nc", "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"], check=False)
    subprocess.run(["chmod", "+x", "cloudflared-linux-amd64"], check=False)
    
    # Start the tunnel
    cmd = f"./cloudflared-linux-amd64 tunnel --url http://127.0.0.1:{port} --metrics localhost:45678"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Parse logs for the URL
    public_url = None
    while True:
        line = process.stderr.readline()
        if not line:
            break
        
        # Look for the *.trycloudflare.com URL
        match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
        if match:
            public_url = match.group(0)
            print(f"\n\n🚀 PUBLIC URL: {public_url}\n   (Use this in JanitorAI/SillyTavern)\n\n")
            break
            
    if not public_url:
        print("❌ Failed to find Cloudflared URL. Check logs.")

if __name__ == '__main__':
    # Start Cloudflared in a background thread
    threading.Thread(target=start_cloudflared, args=(PORT,), daemon=True).start()
    
    # Run Flask app
    app.run(port=PORT)