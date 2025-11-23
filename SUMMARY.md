# FunTimeRouter - Project Summary & Status

## Project Overview
FunTimeRouter is a serverless API proxy (deployed on Vercel) designed to route chat completion requests (OpenAI-compatible) to various upstream providers (OpenAI, OpenRouter, Vertex AI, etc.). It specializes in enhancing the experience for roleplay clients like **JanitorAI** and **SillyTavern**.

## Key Features
1.  **Encrypted Configuration:** Loads provider credentials securely from a remote encrypted file (`providers.enc`) to avoid exposing keys in environment variables.
2.  **Multi-Provider Routing:** Randomly selects providers/models or targets specific ones.
3.  **Protocol Translation:**
    *   **Vertex AI Native:** Translates OpenAI-format requests to Google Vertex AI REST format (`generateContent`).
    *   **DeepSeek R1:** Handles specific reasoning content fields.
4.  **Response Refinement:**
    *   **Thinking Tags:** Wraps reasoning/thought processes (from Gemini 2.5/3.0, DeepSeek R1, Magistral) in `<think>...</think>` tags for UI visualization.
    *   **Prefill Stripping:** Removes "force-start" prefill text (e.g., `((OOC: ...))`) from the final output so users don't see it repeated.
5.  **Security:** Sanitizes headers (`Origin`, `Referer`) to mask the request source.
6.  **Authentication:** Supports automated Google Service Account token generation (`api_key: "AUTO"`).

## Recent Fixes (Session Log)
*   **Vertex AI Support:**
    *   Implemented `convert_openai_to_vertex` to handle system prompt merging (avoiding `systemInstruction` errors on older models) and role mapping.
    *   Implemented `stream_vertex_translation` to parse raw JSON streams from Vertex and convert them to OpenAI SSE format.
    *   Added support for **Service Account Authentication** (generating Bearer tokens on the fly).
    *   Implemented **Global/Regional Endpoint Auto-Correction** (rewriting `aiplatform.googleapis.com` to `us-central1...` or `.../locations/global/...` based on context).
*   **Gemini Thinking:**
    *   Added logic to inject `thinkingConfig` (`includeThoughts: true`, `thinkingBudget: 24576`) for models with "thinking", "2.5", or "gemini-3" in their ID.
    *   Updated parsers to detect `thought` fields in responses (handling both boolean flags and text content) and wrap them in `<think>` tags.
*   **Stream Stability:**
    *   Fixed `stream_sse_stripping` to handle partial buffering and aggressive whitespace stripping.
    *   Fixed `stream_vertex_translation` to handle JSON array parsing robustly (using `raw_decode`) and handle UTF-8 fragmentation across chunks.
    *   Added `data: [DONE]` signal to Vertex streams to prevent client-side 500 errors.
*   **Bug Fixes:**
    *   Fixed `UnboundLocalError` variables (`should_stream`, `is_thinking`, `system_prompt_text`) by correcting scope/initialization.
    *   Fixed `SyntaxError` / `IndentationError` caused by copy-paste edits in `api/index.py`.

## Current Status / Problem at Hand
*   **Status:** The code is syntactically correct and logically complete. Deployment should be successful.
*   **Recent Issue:** JanitorAI was returning a **500 Error** (or empty response) for Vertex AI streaming requests.
    *   **Diagnosis:** This was likely caused by the JSON parser in `stream_vertex_translation` failing on complex input (code blocks) or the stream terminating without the `data: [DONE]` signal.
    *   **Solution Applied:** We replaced the naive parser with `json.JSONDecoder().raw_decode`, added `try-except UnicodeDecodeError` for safety, and ensured `[DONE]` is always yielded.
*   **Next Step:** Verify that JanitorAI now receives a valid stream with `<think>` tags visible for Gemini 2.5/3.0 models.
