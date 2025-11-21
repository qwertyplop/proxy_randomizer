# FunTimeRouter

FunTimeRouter is a secure, Vercel-deployable API proxy designed to route chat completion requests (compatible with OpenAI's API format) to a pool of upstream providers. It is specifically optimized for use with clients like **JanitorAI** and **SillyTavern**.

## 🌟 Features

*   **Multi-Provider Support:** Configure multiple upstream API providers (OpenAI, OpenRouter, local LLMs, etc.).
*   **Randomized Load Balancing:** Automatically selects a random provider and model for each request to distribute load.
*   **Secure Remote Configuration:** Load your sensitive API keys and provider details from an encrypted remote file, keeping your Vercel environment variables clean.
*   **Client Optimizations:**
    *   Specific endpoints for `/janitorai` and `/sillytavern`.
    *   **Prefill Injection:** Automatically injects system prompts or assistant starting text (and strips it from the output) to guide model behavior.
    *   **Mistral Support:** Handles specific formatting (prefixing) for Mistral-based models.
*   **Vercel Ready:** Built to run on Vercel's Serverless functions (free tier compatible).

## 🛠️ Configuration

The router relies on a list of providers to function. You can define these locally for testing or, for better security, host an encrypted configuration file remotely.

### 1. The Provider Format (`providers.json`)

To start, create a `providers.json` file. It should be a list of provider objects:

```json
[
  {
    "name": "OpenRouter",
    "base_url": "https://openrouter.ai/api/v1",
    "api_key": "sk-or-v1-...",
    "models": [
      { 
        "id": "mistralai/mistral-7b-instruct", 
        "enable_prefill": true,
        "settings": { "temperature": 0.8 }
      }
    ]
  },
  {
    "name": "Local-Oobabooga",
    "base_url": "https://your-ngrok-url.ngrok.io/v1",
    "api_key": "dummy",
    "models": [
      { "id": "my-local-model" }
    ]
  }
]
```

### 2. Encrypting Configuration (Recommended)

To avoid storing raw API keys in your source code or Vercel environment variables, use the included utility to encrypt your config.

1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2.  Run the encryption tool:
    ```bash
    python encrypt_config.py
    ```
3.  Enter a strong **Password** when prompted.
4.  The tool will encrypt `providers.json` -> `providers.enc`.
5.  **Upload `providers.enc`** to a public URL (e.g., a GitHub Gist raw link, Discord attachment link, or any direct file host).

## 🚀 Deployment on Vercel

1.  **Fork/Clone** this repository.
2.  **Import** the project into Vercel.
3.  **Environment Variables:** Configure the following in your Vercel Project Settings:

| Variable | Description | Required |
| :--- | :--- | :--- |
| `CONFIG_URL` | The direct URL to your hosted `providers.enc` file. | **Yes** (if using remote config) |
| `CONFIG_PASSWORD` | The password you used to encrypt the file. | **Yes** (if using remote config) |
| `JANITORAI_PREFILL_CONTENT` | Text to force the assistant to start with (e.g., `((OOC: Sure!))`). | No |
| `JANITORAI_SYSTEM_PREFILL_CONTENT`| System prompt to inject. | No |
| `ENABLE_LOGGING` | `true` or `false` to toggle logs. | No (Default: `true`) |

4.  **Deploy!**

## 🔌 Connecting Clients

### JanitorAI
1.  Go to **API Settings** in JanitorAI.
2.  Set the **API URL** to your Vercel deployment: 
    ```
    https://your-project.vercel.app/janitorai
    ```
3.  The proxy handles the keys, so you can often use a dummy key (like `sk-dummy`) in JanitorAI.

### SillyTavern
1.  Select **Chat Completion** or **OpenAI** as the API type.
2.  Set the **API URL** to: 
    ```
    https://your-project.vercel.app/sillytavern
    ```
3.  Click **Connect**.
4.  The proxy will return a generic "Secret" model. Select it and start chatting.

## 💻 Local Development

1.  Clone the repo.
2.  Install dependencies: `pip install -r requirements.txt`
3.  Place your `providers.json` in the root directory OR set `CONFIG_URL` and `CONFIG_PASSWORD` in a `.env` file.
4.  Run the server:
    ```bash
    # For simple testing, you may need to add "app.run()" to the bottom of api/index.py
    python api/index.py
    ```

## ⚠️ Limitations
*   **Vercel Timeouts:** Vercel's free tier has a strict timeout (usually 10s or 60s depending on the function type). If a model takes too long to *start* generating tokens, the connection may drop.
*   **Stateless:** No chat history is stored on the server.
