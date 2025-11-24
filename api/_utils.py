import json
from ._config import GOOGLE_SA_JSON

# Google Auth
try:
    from google.oauth2 import service_account
    import google.auth.transport.requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

_GOOGLE_CREDS_CACHE = None

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
