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
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# Prefill Content
JANITORAI_PREFILL_CONTENT = os.getenv("JANITORAI_PREFILL_CONTENT", "((OOC: Sure, let's proceed!))")
_DEFAULT_SYSTEM_CONTENT = "You are a helpful assistant."
JANITORAI_SYSTEM_PREFILL_CONTENT = os.getenv("JANITORAI_SYSTEM_PREFILL_CONTENT", _DEFAULT_SYSTEM_CONTENT)

_DEFAULT_GLM_CONTENT = """/think
Without writing for / as user. And always write your reasoning in English."""
GLM_SYSTEM_PREFILL_CONTENT = os.getenv("GLM_SYSTEM_PREFILL_CONTENT", _DEFAULT_GLM_CONTENT)

_DEFAULT_GEMINI_CONTENT = "((OOC: Absolutely! Let's proceed, I'll start by thinking with tag *<thought>*, and after ending the thought process with tag *</thought>*, I'll start writing actual response with tag <response>))"
GEMINI_PREFILL_CONTENT = os.getenv("GEMINI_PREFILL_CONTENT", _DEFAULT_GEMINI_CONTENT)
_DEFAULT_GEMINI_ADDITIONAL = "<thought>\n"
GEMINI_PREFILL_ADDITIONAL_CONTENT = os.getenv("GEMINI_PREFILL_ADDITIONAL_CONTENT", _DEFAULT_GEMINI_ADDITIONAL)

_DEFAULT_MAGISTRAL_CONTENT = json.dumps({
  "role": "system",
  "content": [
    {
      "type": "text",
      "text": "# HOW YOU SHOULD THINK AND ANSWER\n\nFirst draft your thinking process (inner monologue) until you arrive at a response. Format your response using Markdown, and use LaTeX for any mathematical equations. Write both your thoughts and the response in the same language as the input.\n\nYour thinking process must follow the template below:"
    },
    {
      "type": "thinking",
      "thinking": [
        {
          "type": "text",
          "text": "Your thoughts or/and draft, like working through an exercise on scratch paper. Be as casual and as long as you want until you are confident to generate the response to the user."
        }
      ]
    },
    {
      "type": "text",
      "text": "Here, provide a self-contained response."
    }
  ]
})
MAGISTRAL_SYSTEM_PREFILL_CONTENT = os.getenv("MAGISTRAL_SYSTEM_PREFILL_CONTENT", _DEFAULT_MAGISTRAL_CONTENT)

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

def stream_sse_stripping(upstream_generator, text_to_strip):
    """
    Parses SSE chunks, extracts content, strips the prefill from the logical start
    of the message, and re-emits valid SSE chunks.
    """
    if not text_to_strip:
        yield from upstream_generator
        return

    target_text = text_to_strip.strip()
    target_len = len(target_text)
    stripped = False
    
    # Helper to re-serialize
    def reserialize(original_data, new_content):
        if "choices" not in original_data or not original_data["choices"]:
             return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")
        original_data["choices"][0]["delta"] = {"content": new_content}
        return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")

    buffer = b""
    accumulated_content = "" 
    check_phase = True 
    cleanup_needed = False # New flag: Active immediately after match to strip trailing junk

    try:
        for chunk in upstream_generator:
            buffer += chunk
            
            while b"\n\n" in buffer:
                split_idx = buffer.find(b"\n\n")
                line = buffer[:split_idx].decode("utf-8", errors="ignore")
                buffer = buffer[split_idx + 2:]
                
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        json_str = line[6:]
                        data = json.loads(json_str)
                        
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        content_chunk = delta.get("content", "")
                        
                        if not content_chunk:
                            yield line.encode("utf-8") + b"\n\n"
                            continue
                        
                        if check_phase:
                            accumulated_content += content_chunk
                            
                            if accumulated_content.startswith(target_text):
                                # Full match found!
                                remainder = accumulated_content[target_len:]
                                check_phase = False 
                                cleanup_needed = True # Start cleanup phase
                                
                                # Process the immediate remainder
                                if remainder:
                                    clean_remainder = remainder.lstrip("/ \n\r")
                                    if clean_remainder:
                                        yield reserialize(data, clean_remainder)
                                        cleanup_needed = False # Real content found, stop cleaning
                                    else:
                                        # Remainder was all junk, stay in cleanup_needed mode
                                        pass
                            
                            elif target_text.startswith(accumulated_content):
                                # Partial match, wait for more
                                pass
                            else:
                                # Mismatch, flush accumulation
                                yield reserialize(data, accumulated_content)
                                check_phase = False
                                
                        elif cleanup_needed:
                            # We matched prefill, now looking for the real start
                            clean_chunk = content_chunk.lstrip("/ \n\r")
                            if clean_chunk:
                                yield reserialize(data, clean_chunk)
                                cleanup_needed = False # Done cleaning
                            else:
                                # Chunk was all junk, drop it
                                pass
                        else:
                            # Normal pass-through
                            yield line.encode("utf-8") + b"\n\n"
                            
                    except Exception as e:
                        print(f"SSE Strip Error: {e}")
                        yield line.encode("utf-8") + b"\n\n"
                else:
                    yield line.encode("utf-8") + b"\n\n"
        
        if buffer:
            yield buffer
            
    except Exception as e:
        print(f"Stream Error: {e}")
        raise e

    except Exception as e:
        print(f"Stream Error: {e}")
        raise e

def stream_gemini_refinement(upstream_generator):
    """
    Injects a fake SSE chunk with <think> at the start,
    and performs naive replacement of </thought> -> </think>.
    """
    # 1. Helper to create a fake SSE chunk
    def make_sse_chunk(content):
        # Minimal OpenAI-compatible chunk
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    # 2. Send the <think> tag as a distinct message delta first
    yield make_sse_chunk("<think>")
    
    # 3. Pass through the rest, naively replacing the closing tag
    # Note: This naive replace might fail if </thought> is split across chunks
    # or escaped strangely, but it's the best we can do without full SSE parsing.
    search_term = b"</thought>"
    replace_term = b"</think>"
    
    try:
        for chunk in upstream_generator:
            # Simple replace on the raw bytes
            if search_term in chunk:
                chunk = chunk.replace(search_term, replace_term)
            yield chunk
            
    except Exception as e:
        print(f"Gemini Stream Error: {e}")
        raise e

def stream_magistral_refinement(upstream_generator, prefill_text=None):
    """
    Parses SSE chunks from Magistral.
    1. Handles 'content' being a list of objects (thinking/text).
    2. Manages <think>...</think> tags based on state changes.
    3. Strips 'prefill_text' if found in the TEXT part of the response.
    4. Reserializes to standard OpenAI SSE format where content is a string.
    """
    
    stripped_prefill = False
    prefill_len = len(prefill_text) if prefill_text else 0
    is_thinking = False
    
    # Helper to re-serialize a chunk with NEW string content
    def reserialize(original_data, new_content):
        if "choices" not in original_data or not original_data["choices"]:
            return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")
        original_data["choices"][0]["delta"] = {"content": new_content}
        return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")

    # Helper to create a fresh SSE chunk for tags
    def make_extra_chunk(content):
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    buffer = b""

    try:
        for chunk in upstream_generator:
            buffer += chunk
            
            while b"\n\n" in buffer:
                split_idx = buffer.find(b"\n\n")
                line = buffer[:split_idx].decode("utf-8", errors="ignore")
                buffer = buffer[split_idx + 2:]
                
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        json_str = line[6:]
                        data = json.loads(json_str)
                        
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        raw_content = delta.get("content", "")
                        
                        output_fragments = []
                        
                        if isinstance(raw_content, list):
                            for item in raw_content:
                                c_type = item.get("type")
                                t_content = ""
                                
                                # Extract text based on type structure
                                if c_type == "thinking":
                                    if "thinking" in item and isinstance(item["thinking"], list):
                                         for sub in item["thinking"]:
                                             if sub.get("type") == "text":
                                                 t_content += sub.get("text", "")
                                    elif "text" in item:
                                         t_content += item.get("text", "")
                                         
                                    if t_content:
                                        if not is_thinking:
                                            output_fragments.append("<think>\n")
                                            is_thinking = True
                                        output_fragments.append(t_content)

                                elif c_type == "text":
                                    t_content = item.get("text", "")
                                    if t_content:
                                        if is_thinking:
                                            output_fragments.append("\n</think>\n")
                                            is_thinking = False
                                        output_fragments.append(t_content)
                                    
                        elif isinstance(raw_content, str) and raw_content:
                             # If raw string received while thinking, assume switch to text
                             if is_thinking:
                                 output_fragments.append("\n</think>\n")
                                 is_thinking = False
                             output_fragments.append(raw_content)
                        
                        # Process output fragments and handle prefill stripping
                        final_chunk_str = ""
                        for frag in output_fragments:
                            # Naive check: If fragment is EXACTLY the closing tag, or contains it?
                            # Fragments are accumulated sequentially.
                            
                            # STRIPPING LOGIC (Simplified for stream)
                            # Only strip if we are NOT thinking and haven't stripped yet.
                            if not is_thinking and not stripped_prefill and prefill_text:
                                # If fragment matches prefill start
                                if frag.startswith(prefill_text):
                                    frag = frag[prefill_len:]
                                    stripped_prefill = True
                                # Partial match handling omitted for brevity/stability
                                
                            final_chunk_str += frag
                        
                        if final_chunk_str:
                            yield reserialize(data, final_chunk_str)
                        
                        # Pass through finish reasons
                        if data.get("choices", [{}])[0].get("finish_reason"):
                            if is_thinking:
                                yield make_extra_chunk("\n</think>\n")
                                is_thinking = False
                            # Yield the finish chunk as is (content might be empty/null)
                            yield f"{line}\n\n".encode("utf-8")
                            
                    except Exception as e:
                        print(f"SSE Parse Error: {e}")
                        yield line.encode("utf-8") + b"\n\n"
                else:
                    if line == "data: [DONE]":
                        if is_thinking:
                             yield make_extra_chunk("\n</think>\n")
                             is_thinking = False
                    yield line.encode("utf-8") + b"\n\n"

        if buffer:
            yield buffer

    except Exception as e:
         print(f"Magistral Stream Error: {e}")
         raise e


def stream_deepseek_refinement(upstream_generator, prefill_text=None):
    """
    Parses SSE chunks from Deepseek (R1).
    1. Handles 'reasoning_content' field.
    2. Wraps reasoning in <think>...</think> tags.
    3. Merges reasoning into the main 'content' stream.
    4. Strips 'prefill_text' if found in the TEXT part of the response.
    """
    
    stripped_prefill = False
    prefill_len = len(prefill_text) if prefill_text else 0
    is_thinking = False
    
    # Helper to re-serialize a chunk with NEW string content
    def reserialize(original_data, new_content):
        if "choices" not in original_data or not original_data["choices"]:
            return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")
        original_data["choices"][0]["delta"] = {"content": new_content}
        # Remove reasoning_content to avoid confusion if client parses it
        if "reasoning_content" in original_data["choices"][0]["delta"]:
             del original_data["choices"][0]["delta"]["reasoning_content"]
        return f"data: {json.dumps(original_data)}\n\n".encode("utf-8")

    # Helper to create a fresh SSE chunk for tags
    def make_extra_chunk(content):
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    buffer = b""

    try:
        for chunk in upstream_generator:
            buffer += chunk
            
            while b"\n\n" in buffer:
                split_idx = buffer.find(b"\n\n")
                line = buffer[:split_idx].decode("utf-8", errors="ignore")
                buffer = buffer[split_idx + 2:]
                
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        json_str = line[6:] # Skip "data: "
                        data = json.loads(json_str)
                        
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        
                        reasoning_chunk = delta.get("reasoning_content", "")
                        content_chunk = delta.get("content", "")
                        
                        # Logic:
                        # If reasoning_content is present, we are thinking.
                        # If content is present, we are (likely) done thinking or interleaved.
                        # Deepseek usually separates them phases.
                        
                        output_text = ""
                        
                        # Handle Reasoning
                        if reasoning_chunk:
                            if not is_thinking:
                                output_text += "<think>\n"
                                is_thinking = True
                            output_text += reasoning_chunk
                        
                        # Handle Content
                        if content_chunk:
                            if is_thinking:
                                output_text += "\n</think>\n"
                                is_thinking = False
                            
                            # Prefill Stripping (only on content)
                            if prefill_text and not stripped_prefill:
                                # Simple check on the chunk itself
                                if content_chunk.startswith(prefill_text):
                                    content_chunk = content_chunk[prefill_len:]
                                    stripped_prefill = True
                                    # Also strip leading junk if we just stripped prefill
                                    content_chunk = content_chunk.lstrip("/ \n\r")
                                elif prefill_text.startswith(content_chunk):
                                    # Partial match logic omitted for simplicity (assume full chunk usually)
                                    pass
                                
                            output_text += content_chunk
                            
                        if output_text:
                            yield reserialize(data, output_text)
                        elif not reasoning_chunk and not content_chunk:
                             # Check finish reason to close tags
                             if data.get("choices", [{}])[0].get("finish_reason"):
                                 if is_thinking:
                                     yield make_extra_chunk("\n</think>\n")
                                     is_thinking = False
                                 yield f"{line}\n\n".encode("utf-8")

                    except Exception as e:
                        print(f"Deepseek Parse Error: {e}")
                        yield line.encode("utf-8") + b"\n\n"
                else:
                    if line == "data: [DONE]":
                        if is_thinking:
                             yield make_extra_chunk("\n</think>\n")
                             is_thinking = False
                    yield line.encode("utf-8") + b"\n\n"

        if buffer:
            yield buffer

    except Exception as e:
         print(f"Deepseek Stream Error: {e}")
         raise e

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
    # Assuming "gemini-3" or specific reasoning models need this
    if "gemini-3" in model_id or "thinking" in model_id:
         vertex_body["generationConfig"]["thinkingConfig"] = {"thinkingLevel": "HIGH"}

    system_instruction = None
    
    for msg in openai_body.get("messages", []):
        role = msg.get("role")
        content = msg.get("content", "")
        
        if role == "system":
            # Vertex supports system_instruction separately
            if system_instruction is None:
                system_instruction = {"parts": []}
            system_instruction["parts"].append({"text": content})
        elif role == "user":
            vertex_body["contents"].append({"role": "user", "parts": [{"text": content}]})
        elif role == "assistant":
            vertex_body["contents"].append({"role": "model", "parts": [{"text": content}]})
            
    if system_instruction:
        vertex_body["systemInstruction"] = system_instruction
        
    return vertex_body

def stream_vertex_translation(upstream_response):
    """
    Translates Vertex AI's JSON stream (array of objects) to OpenAI SSE format.
    Vertex returns a valid JSON array if waited for, but streams individual JSON objects
    separated by commas or brackets. We need to parse strictly.
    """
    # Helper to create a fresh SSE chunk
    def make_sse(content):
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    buffer = b""
    is_thinking = False
    
    # Vertex stream format is often: [{...}, \n {...}, \n ...]
    # It's tricky to parse purely line-by-line because of the formatting.
    # We will try to extract balanced JSON objects.
    
    try:
        for chunk in upstream_response.iter_content(chunk_size=1024):
            if not chunk: continue
            buffer += chunk
            
            while True:
                # Try to find a complete JSON object.
                # Simple heuristic: Look for matching braces { }
                # This is brittle for nested objects but Vertex top-level chunks are usually flat-ish
                # except for the content parts.
                
                start_idx = buffer.find(b"{")
                if start_idx == -1:
                    # No start brace, discard garbage (e.g. [ or ,)
                    if len(buffer) > 10 and b"[" in buffer: 
                         buffer = buffer[buffer.find(b"[")+1:] # Skip start of array
                         continue
                    break
                
                # We have a start brace. Now find end brace.
                # We need to count depth to handle nested braces.
                depth = 0
                end_idx = -1
                for i in range(start_idx, len(buffer)):
                    if buffer[i] == 123: # '{'
                        depth += 1
                    elif buffer[i] == 125: # '}'
                        depth -= 1
                        if depth == 0:
                            end_idx = i
                            break
                
                if end_idx != -1:
                    # We found a complete object
                    json_bytes = buffer[start_idx : end_idx+1]
                    buffer = buffer[end_idx+1:] # Advance buffer
                    
                    try:
                        data = json.loads(json_bytes)
                        candidates = data.get("candidates", [])
                        if candidates:
                            cand = candidates[0]
                            parts = cand.get("content", {}).get("parts", [])
                            
                            for part in parts:
                                text = part.get("text", "")
                                thought = part.get("thought", "") # Hypothetical: Check documentation for 'thought' field name
                                # Vertex thinking models usually put thoughts in 'thought' or special part type?
                                # "parts": [{"text": "..."}] is standard.
                                # If reasoning is used, Vertex might return mixed parts or a separate field.
                                # Per `vertex.txt` Python example, it just prints `chunk.text`.
                                # Does `chunk.text` include thoughts?
                                # If we assume it's standard text generation, we pass it through.
                                # If "thinking" is enabled, we need to know how Vertex sends it.
                                # Assuming for now it's just text or we don't distinguish.
                                # BUT, if we want <think> tags, we need to know.
                                # If Vertex merges them, we can't separate easily without parsing the text itself.
                                # Let's assume standard text passthrough for now.
                                
                                if text:
                                    yield make_sse(text)
                                    
                    except Exception as e:
                        print(f"Vertex JSON Parse Error: {e}")
                else:
                    # Incomplete object, wait for more data
                    break
                    
    except Exception as e:
        print(f"Vertex Stream Error: {e}")
        raise e

def proxy_request(source_label, upstream_path_suffix):
    timestamp = datetime.now().isoformat()
    
    # 1. Load Providers
    providers = load_providers()
    
    # 2. Pre-scan Request for Admin Bypass
    incoming_key = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    requested_model_id = None
    
    # We need to peek at the body to see the requested model.
    # request.get_json() is safe to call multiple times.
    if request.is_json:
        try:
            body_peek = request.get_json()
            requested_model_id = body_peek.get("model")
        except:
            pass

    provider = None
    model_config = None

    # 3. Select Provider (Admin Specific or Random)
    if ADMIN_PASSWORD and incoming_key == ADMIN_PASSWORD and requested_model_id:
        print(f"🔒 Admin Access: Attempting to find specific model '{requested_model_id}'")
        for p in providers:
            if "models" in p:
                for m in p["models"]:
                    if m["id"] == requested_model_id:
                        provider = p
                        model_config = m
                        break
            if provider: break
        
        if not provider:
             print(f"⚠️ Admin Access: Model '{requested_model_id}' not found in providers. Falling back to random.")

    if not provider or not model_config:
        provider, model_config = select_random_provider(providers)
    
    if not provider or not model_config:
        return jsonify({"error": "Configuration Error: No providers available (Decryption failed or empty list)."}), 500

    provider = None
    model_config = None

    # 3. Select Provider (Admin Specific or Random)
    if ADMIN_PASSWORD and incoming_key == ADMIN_PASSWORD and requested_model_id:
        print(f"🔒 Admin Access: Attempting to find specific model '{requested_model_id}'")
        for p in providers:
            if "models" in p:
                for m in p["models"]:
                    if m["id"] == requested_model_id:
                        provider = p
                        model_config = m
                        break
            if provider: break
        
        if not provider:
             print(f"⚠️ Admin Access: Model '{requested_model_id}' not found in providers. Falling back to random.")

    if not provider or not model_config:
        provider, model_config = select_random_provider(providers)
    
    if not provider or not model_config:
        return jsonify({"error": "Configuration Error: No providers available (Decryption failed or empty list)."}), 500

    base_url = provider.get("base_url", "").rstrip("/")
    target_url = f"{base_url}{upstream_path_suffix}"
    
    # Correct Detection logic:
    # 1. Provider name or URL implies Vertex/Google
    # 2. BUT NOT if it is the 'openapi' endpoint (Third-party models on Vertex use OpenAI protocol)
    is_vertex = ("vertex" in provider.get("name", "").lower() or "googleapis.com" in base_url) and "/openapi/" not in base_url
    
    if is_vertex:
        # Vertex API Construction
        # Base URL expected in providers.json: "https://aiplatform.googleapis.com/v1/publishers/google/models"
        # OR constructs it from project info if we add that to config.
        # Let's assume base_url is the root "https://aiplatform.googleapis.com"
        # and we build the path: /v1/publishers/google/models/{MODEL_ID}:streamGenerateContent?key={API_KEY}
        
        # Actually, let's rely on the providers.json to have the FULL base URL up to .../models/
        # Example Base URL: "https://aiplatform.googleapis.com/v1/publishers/google/models"
        
        model_id = model_config.get("id")
        api_key = provider.get("api_key")
        target_url = f"{base_url}/{model_id}:streamGenerateContent?key={api_key}"
    
    # DEBUG LOGGING
    print(f"\n[{timestamp}] 🚀 ATTEMPTING REQUEST")
    print(f"   Source: {source_label}")
    print(f"   Provider: {provider.get('name')} | Model: {model_config.get('id')}")
    print(f"   Base URL (Config): {base_url}")
    print(f"   Target URL (Final): {target_url}")

    excluded_headers = ["content-length", "host", "origin", "referer", "cookie", "user-agent", "x-forwarded-for", "x-forwarded-host", "accept-encoding", "authorization"]
    clean_headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    
    # SANITIZATION: Enforce generic headers to hide origin
    clean_headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"
    
    if is_vertex:
        # Vertex usually expects Content-Type
        clean_headers["Content-Type"] = "application/json"
        # API Key is in URL, header auth might conflict if we send Bearer with it.
        # Remove Auth header for Vertex if using URL key
        if "Authorization" in clean_headers:
            del clean_headers["Authorization"]
    else:
        clean_headers["Authorization"] = f"Bearer {provider.get('api_key', '')}"
        
    clean_headers["Origin"] = "https://localhost" 
    clean_headers["Referer"] = "https://localhost/" 

    json_body = None
    data_body = None
    should_stream = True
    prefill_used = None

    if request.is_json:
        try:
            incoming_body = request.get_json()
            should_stream = incoming_body.get("stream", True)
            
            json_body = {
                "messages": incoming_body.get("messages", []),
                "stream": should_stream
            }
            
            # Start with the SELECTED model config
            json_body["model"] = model_config.get("id")
            
            # DeepSeek Terminus Specific: Enable thinking
            if "terminus" in model_config.get("id", "").lower():
                json_body["chat_template_kwargs"] = {"thinking": True}
            
            if "settings" in model_config:
                for k, v in model_config["settings"].items():
                    json_body[k] = v
            
            if source_label == "janitorai" and isinstance(json_body["messages"], list):
                enable_prefill = model_config.get("enable_prefill", False)
                if enable_prefill:
                    # Determine System Prompt
                    model_id_lower = model_config.get("id", "").lower()
                    system_content = JANITORAI_SYSTEM_PREFILL_CONTENT
                    
                    if "glm-4" in model_id_lower and "4.5" not in model_id_lower:
                        system_content = GLM_SYSTEM_PREFILL_CONTENT

                    # Determine specific logic for Magistral
                    if "magistral" in model_id_lower:
                         try:
                             # Magistral uses a complex object for system prompt
                             system_msg_obj = json.loads(MAGISTRAL_SYSTEM_PREFILL_CONTENT)
                             json_body["messages"].append(system_msg_obj)
                         except:
                             # Fallback if config is just text
                             json_body["messages"].append({"role": "system", "content": MAGISTRAL_SYSTEM_PREFILL_CONTENT})
                    else:
                        # Inject Standard System Prompt at the end (Override)
                        json_body["messages"].append({"role": "system", "content": system_content})
                    
                    # Prepare Assistant Prefill
                    prefill_used = JANITORAI_PREFILL_CONTENT
                    
                    if "gemini" in model_id_lower:
                        prefill_used = GEMINI_PREFILL_CONTENT
                        
                    ass_msg = {"role": "assistant", "content": prefill_used}
                    
                    # Mistral Specific: Requires 'prefix': True if the last message is Assistant
                    is_mistral = "mistral" in provider.get("base_url", "") or "mistral" in model_config.get("id", "")
                    if is_mistral:
                        ass_msg["prefix"] = True
                        
                    json_body["messages"].append(ass_msg)
                    
                    if "gemini" in model_id_lower:
                        # Add additional assistant message for Gemini
                        json_body["messages"].append({"role": "assistant", "content": GEMINI_PREFILL_ADDITIONAL_CONTENT})
                        pass
            
            # VERTEX TRANSLATION
            if is_vertex:
                json_body = convert_openai_to_vertex(json_body, model_config.get("id", ""))

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
            
            # Vertex Response Handling
            if is_vertex:
                return Response(stream_with_context(stream_vertex_translation(resp)), resp.status_code, headers)

            def generate():
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk: yield chunk
            
            final_generator = generate()
            
            is_magistral = "magistral" in model_config.get("id", "").lower()
            is_deepseek = "deepseek" in model_config.get("id", "").lower()
            
            # NOTE: Prefill stripping is broken for SSE streams (it expects raw text).
            # We disable it for now or leave as is if user relies on raw-text backends.
            if prefill_used and resp.status_code == 200 and not is_magistral and not is_deepseek and not is_vertex:
                 # Use SSE-aware stripping instead of raw byte stripping
                 final_generator = stream_sse_stripping(final_generator, prefill_used)

            if "gemini" in model_config.get("id", "").lower() and resp.status_code == 200 and not is_vertex:
                final_generator = stream_gemini_refinement(final_generator)
            
            if is_magistral and resp.status_code == 200:
                final_generator = stream_magistral_refinement(final_generator, prefill_used)
                
            if is_deepseek and resp.status_code == 200:
                final_generator = stream_deepseek_refinement(final_generator, prefill_used)

            return Response(stream_with_context(final_generator), resp.status_code, headers)

    json_body = None
    data_body = None
    should_stream = True
    prefill_used = None

    if request.is_json:
        try:
            incoming_body = request.get_json()
            should_stream = incoming_body.get("stream", True)
            
            json_body = {
                "messages": incoming_body.get("messages", []),
                "stream": should_stream
            }
            
            # Start with the SELECTED model config
            json_body["model"] = model_config.get("id")
            
            # DeepSeek Terminus Specific: Enable thinking
            if "terminus" in model_config.get("id", "").lower():
                json_body["chat_template_kwargs"] = {"thinking": True}
            
            if "settings" in model_config:
                for k, v in model_config["settings"].items():
                    json_body[k] = v
            
            if source_label == "janitorai" and isinstance(json_body["messages"], list):
                enable_prefill = model_config.get("enable_prefill", False)
                if enable_prefill:
                    # Determine System Prompt
                    model_id_lower = model_config.get("id", "").lower()
                    system_content = JANITORAI_SYSTEM_PREFILL_CONTENT
                    
                    if "glm-4" in model_id_lower and "4.5" not in model_id_lower:
                        system_content = GLM_SYSTEM_PREFILL_CONTENT

                    # Determine specific logic for Magistral
                    if "magistral" in model_id_lower:
                         try:
                             # Magistral uses a complex object for system prompt
                             system_msg_obj = json.loads(MAGISTRAL_SYSTEM_PREFILL_CONTENT)
                             json_body["messages"].append(system_msg_obj)
                         except:
                             # Fallback if config is just text
                             json_body["messages"].append({"role": "system", "content": MAGISTRAL_SYSTEM_PREFILL_CONTENT})
                    else:
                        # Inject Standard System Prompt at the end (Override)
                        json_body["messages"].append({"role": "system", "content": system_content})
                    
                    # Prepare Assistant Prefill
                    prefill_used = JANITORAI_PREFILL_CONTENT
                    
                    if "gemini" in model_id_lower:
                        prefill_used = GEMINI_PREFILL_CONTENT
                        
                    ass_msg = {"role": "assistant", "content": prefill_used}
                    
                    # Mistral Specific: Requires 'prefix': True if the last message is Assistant
                    is_mistral = "mistral" in provider.get("base_url", "") or "mistral" in model_config.get("id", "")
                    if is_mistral:
                        ass_msg["prefix"] = True
                        
                    json_body["messages"].append(ass_msg)
                    
                    if "gemini" in model_id_lower:
                        # Add additional assistant message for Gemini
                        json_body["messages"].append({"role": "assistant", "content": GEMINI_PREFILL_ADDITIONAL_CONTENT})
                        pass

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
            
            final_generator = generate()
            
            is_magistral = "magistral" in model_config.get("id", "").lower()
            is_deepseek = "deepseek" in model_config.get("id", "").lower()
            
            # NOTE: Prefill stripping is broken for SSE streams (it expects raw text).
            # We disable it for now or leave as is if user relies on raw-text backends.
            if prefill_used and resp.status_code == 200 and not is_magistral and not is_deepseek:
                 # Use SSE-aware stripping instead of raw byte stripping
                 final_generator = stream_sse_stripping(final_generator, prefill_used)

            if "gemini" in model_config.get("id", "").lower() and resp.status_code == 200:
                final_generator = stream_gemini_refinement(final_generator)
            
            if is_magistral and resp.status_code == 200:
                final_generator = stream_magistral_refinement(final_generator, prefill_used)
                
            if is_deepseek and resp.status_code == 200:
                final_generator = stream_deepseek_refinement(final_generator, prefill_used)

            return Response(stream_with_context(final_generator), resp.status_code, headers)
        else:
            content = resp.content
            if "gemini" in model_config.get("id", "").lower() and resp.status_code == 200:
                try:
                    # Parse JSON, modify content, re-serialize
                    body = json.loads(content)
                    if "choices" in body and len(body["choices"]) > 0:
                        msg = body["choices"][0].get("message", {})
                        if "content" in msg and msg["content"]:
                            new_content = "<think>" + msg["content"].replace("</thought>", "</think>")
                            body["choices"][0]["message"]["content"] = new_content
                            content = json.dumps(body).encode("utf-8")
                except Exception as e:
                    print(f"⚠️ Failed to refine non-streaming Gemini response: {e}")
                    # Fallback: Return original content if parsing fails
            
            return Response(content, resp.status_code, headers)

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

