# Universal Rerouter - Vercel Edition

This version is adapted to run on [Vercel](https://vercel.com) (Free Tier compatible).

## 🚀 Deployment Instructions

1.  **Install Vercel CLI** (Optional, easier to use dashboard):
    ```bash
    npm i -g vercel
    ```

2.  **Login to Vercel:**
    *   Go to [vercel.com](https://vercel.com) and sign up/login.
    *   Or use CLI: `vercel login`

3.  **Deploy:**
    *   **Option A (Web Dashboard):**
        1.  Push this `vercel_proxy` folder to a GitHub repository.
        2.  Import that repository in Vercel.
        3.  Vercel will automatically detect the Python project.
        4.  Click **Deploy**.

    *   **Option B (CLI):**
        1.  Open a terminal in this folder: `cd vercel_proxy`
        2.  Run `vercel`
        3.  Follow the prompts (Yes to everything).

## ⚙️ Configuration (Environment Variables)

You can configure the proxy settings without editing the code by using **Environment Variables** in your Vercel project settings.

**To add variables:**
1.  Go to your Project Settings on Vercel.
2.  Click **Environment Variables**.
3.  Add any of the following Key-Value pairs:

| Variable Key | Description | Default Value |
| :--- | :--- | :--- |
| `TARGET_UPSTREAM` | The API URL to forward requests to. | `https://api.openai.com/v1/chat/completions` |
| `ENABLE_JANITORAI_PREFILL` | Set to `true` to inject an Assistant message at the end of the history. | `false` |
| `JANITORAI_PREFILL_CONTENT` | The content of the Assistant prefill message. | `((OOC: Sure, let's proceed!))` |
| `ENABLE_JANITORAI_SYSTEM_PREFILL` | Set to `true` to inject a System prompt at the end of the history. | `false` |
| `JANITORAI_SYSTEM_PREFILL_CONTENT` | The content of the System prefill message. | *(A long default roleplay prompt)* |
| `ENABLE_LOGGING` | Set to `false` to disable logging to Vercel console. | `true` |

*(You must redeploy your project for new variables to take effect - usually by going to Deployments -> Redeploy).*

## ⚠️ Important Vercel Limitations

1.  **Timeouts:** Vercel Free Tier functions have a **10-second timeout**.
    *   If the upstream API (OpenAI/etc) takes longer than 10 seconds to *start* sending a response, the request might fail.
    *   Streaming helps, but keep responses short if possible.
2.  **No Persistent Logs:** Logs are viewed in the Vercel Dashboard under the "Logs" tab of your deployment. They are not saved to files.
3.  **Cold Starts:** The first request after a while might take 2-3 seconds longer to start up.