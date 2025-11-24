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

# Google Auth
try:
    from google.oauth2 import service_account
    import google.auth.transport.requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

# ============================================================================ 
# ⚙️ CONFIGURATION
# ============================================================================ 

ENABLE_LOGGING = os.getenv("ENABLE_LOGGING", "true").lower() == "true"

# Remote Config
CONFIG_URL = os.getenv("CONFIG_URL", "")
CONFIG_PASSWORD = os.getenv("CONFIG_PASSWORD", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
GOOGLE_SA_JSON = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")

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
_GOOGLE_CREDS_CACHE = None

app = Flask(__name__)
CORS(app)

def get_google_access_token():
    """
    Generates a fresh Google Access Token using Service Account credentials
    stored in the GOOGLE_SERVICE_ACCOUNT_JSON environment variable.
    """
    global _GOOGLE_CREDS_CACHE
    
    if not GOOGLE_AUTH_AVAILABLE:
        print("⚠️ Google Auth libraries not installed. Cannot auto-generate tokens.")
        return None

    if not GOOGLE_SA_JSON:
        print("⚠️ GOOGLE_SERVICE_ACCOUNT_JSON env var not set.")
        return None

    try:
        if _GOOGLE_CREDS_CACHE is None:
            info = json.loads(GOOGLE_SA_JSON)
            _GOOGLE_CREDS_CACHE = service_account.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
        
        creds = _GOOGLE_CREDS_CACHE
        
        # Refresh if expired or no token
        if not creds.valid:
            request_adapter = google.auth.transport.requests.Request()
            creds.refresh(request_adapter)
            
        return creds.token
        
    except Exception as e:
        print(f"❌ Failed to generate Google Token: {e}")
        return None

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
    try:
        for chunk in upstream_generator:
            # LOGGING: Raw chunk
            # print(f"RAW CHUNK: {chunk[:100]}", flush=True)
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
        # raise e <--- REMOVED to prevent 500 crashes on partial failures

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
                        json_str = line[6:] # Skip "data: "
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
                            # STRIPPING LOGIC (Simplified for stream)
                            # Only strip if we are NOT thinking and haven't stripped yet.
                            if not is_thinking and not stripped_prefill and prefill_text:
                                # If fragment matches prefill start
                                if frag.startswith(prefill_text):
                                    frag = frag[prefill_len:]
                                    stripped_prefill = True
                                    # Also strip immediate punctuation
                                    frag = frag.lstrip("/ \n\r")
                                # Partial match handling omitted for brevity
                                
                            final_chunk_str += frag
                        
                        if final_chunk_str:
                            yield reserialize(data, final_chunk_str)
                        
                        # Pass through finish reasons
                        if data.get("choices", [{}])[0].get("finish_reason"):
                            if is_thinking:
                                yield make_extra_chunk("\n</think>\n")
                                is_thinking = False
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
                                if content_chunk.startswith(prefill_text):
                                    content_chunk = content_chunk[prefill_len:]
                                    stripped_prefill = True
                                    content_chunk = content_chunk.lstrip("/ \n\r")
                                elif prefill_text.startswith(content_chunk):
                                    pass
                                
                            output_text += content_chunk
                            
                        if output_text:
                            yield reserialize(data, output_text)
                        elif not reasoning_chunk and not content_chunk:
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
    # Only enable if the model ID explicitly suggests reasoning capabilities
    if "thinking" in model_id.lower() or "gemini-3" in model_id.lower() or "2.5" in model_id.lower():
        print(f"🧠 Enabling Thinking Config for {model_id}")
        t_config = {"includeThoughts": True}
        
        # User requested: Budget for 2.5, Level for 3
        if "2.5" in model_id:
            t_config["thinkingBudget"] = 24576 
        elif "gemini-3" in model_id:
            t_config["thinkingLevel"] = "HIGH"
        else:
            # Default fallback for other thinking models (like 2.0 Flash Thinking)
            t_config["thinkingLevel"] = "HIGH"
            
        vertex_body["generationConfig"]["thinkingConfig"] = t_config

    system_instruction = None
    system_prompt_text = "" # Initialize variable
    
    for msg in openai_body.get("messages", []):
        role = msg.get("role")
        content = msg.get("content", "")
        
        if role == "system":
            # Collect system prompt to prepend to first user message
            system_prompt_text += content + "\n\n"
        elif role == "user":
            vertex_body["contents"].append({"role": "user", "parts": [{"text": content}]})
        elif role == "assistant":
            vertex_body["contents"].append({"role": "model", "parts": [{"text": content}]})
            
    # Ensure conversation starts with 'user' role and inject system prompt
    if vertex_body["contents"]:
        if vertex_body["contents"][0]["role"] == "model":
            # If starts with model, insert dummy user with system prompt
            initial_text = (system_prompt_text + "[Conversation Started]").strip()
            vertex_body["contents"].insert(0, {"role": "user", "parts": [{"text": initial_text}]})
        else:
            # If starts with user, prepend system prompt to it
            if system_prompt_text:
                original_text = vertex_body["contents"][0]["parts"][0]["text"]
                vertex_body["contents"][0]["parts"][0]["text"] = system_prompt_text + original_text
    else:
        # Empty conversation?
        if system_prompt_text:
             vertex_body["contents"].append({"role": "user", "parts": [{"text": system_prompt_text}]})

    # vertex_body["systemInstruction"] is NOT used to avoid 400 errors on models that don't support it.
        
    return vertex_body
        
    return vertex_body

def stream_vertex_translation(upstream_response):
    """
    Translates Vertex AI's JSON stream (array of objects) to OpenAI SSE format.
    """
    def make_sse(content):
        data = {
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None
            }]
        }
        return f"data: {json.dumps(data)}\n\n".encode("utf-8")

    # Check for immediate upstream error
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
    
    # Send initial role chunk (OpenAI Standard)
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
            
            if first_chunk:
                print(f"🔍 Vertex Raw Stream Start: {chunk[:500]}", flush=True)
                first_chunk = False
            
            buffer += chunk
            
            while True:
                try:
                    # Attempt to decode the buffer
                    buffer_str = buffer.decode("utf-8")
                except UnicodeDecodeError:
                    break
                
                # Search for start of JSON object
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
                    
                    # Process Object
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
                
        # Ensure thinking is closed at end of stream
        if is_thinking:
             yield make_sse("\n</think>\n")
        
        # Send final chunk with finish_reason="stop"
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
        # Do not raise e here; we handled it by sending the error to the client.
        # Raising it would crash the WSGI handler and cause a 500 Error.

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
            "id": "chatcmpl-vertex-" + str(random.randint(100000, 999999)),
            "object": "chat.completion",
            "created": int(datetime.now().timestamp()),
            "model": "vertex-gemini", # Placeholder
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
                "prompt_tokens": 0, # We don't parse metadata yet
                "completion_tokens": 0,
                "total_tokens": 0
            }
        }
        return json.dumps(openai_resp).encode("utf-8")
        
    except Exception as e:
        print(f"❌ Vertex Non-Stream Translation Error: {e}")
        return raw_content # Fallback to raw if parsing fails

def handle_vertex_request(req, provider, model_config):
    """
    Specialized handler for Vertex AI that strictly mimics the working Colab debugger logic.
    """
    timestamp = datetime.now().isoformat()
    print(f"\n[{timestamp}] ⚡ VERTEX HANDLER ENGAGED")
    
    # 1. Parse Input
    try:
        req_body = req.get_json(force=True)
        is_stream = req_body.get("stream", True)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    # 2. Authenticate (Service Account Only for now as per our setup)
    token = get_google_access_token()
    if not token:
        return jsonify({"error": "Failed to generate Google Token. Check JSON config."}), 500

    # 3. Translate Body
    model_id = model_config.get("id")
    vertex_body = convert_openai_to_vertex(req_body, model_id)
    
    # 4. Construct URL
    # Extract Project ID/Location from SA JSON or Config
    project_id = ""
    location = "global" # Default
    
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
    # Add more regions if needed from config
    
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

    # 5. Send to Vertex
    try:
        if is_stream:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=True, timeout=60)
            
            # CORS Headers specifically for this response
            response_headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Content-Type": "text/event-stream"
            }
            
            return Response(
                stream_vertex_translation(resp),
                status=resp.status_code,
                headers=response_headers
            )
        else:
            resp = requests.post(url, headers=headers, json=vertex_body, stream=False, timeout=60)
            
            translated = translate_vertex_non_stream(resp.content)
            
            response_headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Content-Type": "application/json"
            }
            
            return Response(translated, status=resp.status_code, headers=response_headers)

    except Exception as e:
        print(f"Vertex Request Failed: {e}")
        return jsonify({"error": f"Vertex Request Failed: {e}"}), 500

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
    excluded_headers = ["content-length", "host", "origin", "referer", "cookie", "user-agent", "x-forwarded-for", "x-forwarded-host", "accept-encoding", "authorization"]
    clean_headers = {k: v for k, v in req.headers.items() if k.lower() not in excluded_headers}
    
    clean_headers["User-Agent"] = "Mozilla/5.0 (compatible; FunTimeRouter/1.0)"
    clean_headers["Origin"] = "https://localhost"
    
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
                            system_content = MAGISTRAL_SYSTEM_PREFILL_CONTENT # Fallback if not valid JSON string
                    
                    # Inject System Message (if object or string)
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
                    
                    # Gemini Additional Tag
                    if "gemini" in model_id_lower:
                        json_body["messages"].append({"role": "assistant", "content": GEMINI_PREFILL_ADDITIONAL_CONTENT})

        except Exception as e:
            print(f"⚠️ JSON Parse/Modify Error: {e}")
            # Fallback to raw data if modification fails
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
            timeout=60
        )
        
        print(f"   ✅ Upstream Status: {resp.status_code}")
        
        # 5. Prepare Response Headers
        excluded_resp_headers = ["content-encoding", "content-length", "transfer-encoding", "connection", "content-type"]
        headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_resp_headers]
        
        headers.append(("X-FunTime-Provider", provider.get("name")))
        headers.append(("X-FunTime-Model", model_config.get("id")))
        
        # CORS & Buffering
        headers.append(("Access-Control-Allow-Origin", "*"))
        headers.append(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        headers.append(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        headers.append(("Cache-Control", "no-cache"))
        headers.append(("X-Accel-Buffering", "no"))

        # 6. Stream Back (PURE STREAMING - No Stripping)
        if should_stream:
            def generate():
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk: yield chunk
            
            return Response(generate(), resp.status_code, headers, mimetype='text/event-stream')
        else:
            return Response(resp.content, resp.status_code, headers, mimetype='application/json')

    except Exception as e:
        print(f"   ❌ Generic Request Failed: {e}")
        return jsonify({"error": f"Generic Proxy Error: {str(e)}"}), 500

def proxy_request(source_label, upstream_path_suffix):
    timestamp = datetime.now().isoformat()
    
    # 1. Load Providers
    providers = load_providers()
    
    # Initialize variables early
    json_body = None
    
    # Parse Request Body First
    if request.is_json:
        try:
            json_body = request.get_json()
            requested_model_id = json_body.get("model")
        except Exception as e:
            print(f"⚠️ Error parsing JSON body: {e}")
            requested_model_id = None
    else:
        requested_model_id = None

    # 2. Pre-scan for Admin Bypass
    incoming_key = request.headers.get("Authorization", "").replace("Bearer ", "").strip()

    provider = None
    model_config = None

    # 3. Select Provider
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
    
    # Correct Detection logic:
    is_vertex = ("vertex" in provider.get("name", "").lower() or "googleapis.com" in base_url) and "/openapi" not in base_url
    
    if is_vertex:
        # Delegate to specialized Vertex Handler
        return handle_vertex_request(request, provider, model_config)
    
    # Delegate to Generic Handler
    return handle_generic_request(request, provider, model_config, source_label, upstream_path_suffix)

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
    
@app.route("/"+"<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def catch_all(path):
    print(f"⚠️ Catch-All hit: {path}")
    return jsonify({"error": f"Catch-All: Route not found: {path}", "method": request.method}), 404