"""
ngrok_router.py
Manages a pyngrok tunnel that exposes the local vulnerable Security Lab
(port 8080) via a public ngrok URL.

Only the Security Lab port (8080) is ever tunnelled — never production services.
"""
import threading
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

# ─── State ────────────────────────────────────────────────────────────────────

_tunnel_lock   = threading.Lock()
_tunnel        = None   # active pyngrok tunnel object
_public_url: Optional[str] = None
_auth_token: Optional[str] = None   # set once by the user


class NgrokTokenRequest(BaseModel):
    auth_token: str


class NgrokStatus(BaseModel):
    running: bool
    public_url: Optional[str]
    local_port: int
    region: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

LAB_PORT = 8080


def _try_import_pyngrok():
    try:
        from pyngrok import ngrok, conf
        return ngrok, conf
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="pyngrok not installed. Run: pip install pyngrok",
        )


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/status", response_model=NgrokStatus)
async def get_tunnel_status():
    """Return current ngrok tunnel status."""
    return NgrokStatus(
        running=_public_url is not None,
        public_url=_public_url,
        local_port=LAB_PORT,
        region="auto",
    )


@router.post("/set-token")
async def set_auth_token(body: NgrokTokenRequest):
    """Save the ngrok auth-token in memory (not persisted to disk)."""
    global _auth_token
    _auth_token = body.auth_token.strip()
    return {"status": "token saved", "masked": f"{_auth_token[:8]}..."}


@router.post("/start", response_model=NgrokStatus)
async def start_tunnel():
    """
    Start an ngrok tunnel on the Security Lab port (8080).
    The caller must have already set a token via POST /api/ngrok/set-token,
    OR have ngrok configured globally via `ngrok config add-authtoken`.
    """
    global _tunnel, _public_url

    with _tunnel_lock:
        if _public_url:
            return NgrokStatus(running=True, public_url=_public_url, local_port=LAB_PORT, region="auto")

        ngrok_mod, conf_mod = _try_import_pyngrok()

        # Apply auth token if provided
        if _auth_token:
            ngrok_mod.set_auth_token(_auth_token)

        try:
            # Modern pyngrok connect - specify port/addr and protocol
            tunnel = ngrok_mod.connect(LAB_PORT, "http")
            _tunnel = tunnel
            raw_url = getattr(tunnel, "public_url", None)
            
            if not raw_url or not isinstance(raw_url, str):
                raise ValueError(
                    "ngrok failed to provide a public URL. Ensure you have set a valid ngrok auth token via /api/ngrok/set-token."
                )

            # Ensure HTTPS URL
            if raw_url.startswith("http://"):
                _public_url = raw_url.replace("http://", "https://", 1)
            else:
                _public_url = raw_url

        except Exception as exc:
            _tunnel = None
            _public_url = None
            raise HTTPException(status_code=500, detail=f"ngrok error: {exc}")

    return NgrokStatus(running=True, public_url=_public_url, local_port=LAB_PORT, region="auto")


@router.post("/stop")
async def stop_tunnel():
    """Disconnect the active ngrok tunnel."""
    global _tunnel, _public_url

    with _tunnel_lock:
        if not _tunnel and not _public_url:
            return {"status": "no tunnel running"}
        ngrok_mod, _ = _try_import_pyngrok()
        
        target_url = getattr(_tunnel, "public_url", None) or _public_url
        if target_url and isinstance(target_url, str):
            try:
                ngrok_mod.disconnect(target_url)
            except Exception:
                pass
        try:
            ngrok_mod.kill()
        except Exception:
            pass
        _tunnel = None
        _public_url = None

    return {"status": "tunnel stopped"}


@router.get("/ip-analysis")
async def proxy_ip_analysis(limit: int = 50):
    """
    Proxy the Security Lab's /api/ip-log endpoint through the backend
    so the frontend doesn't need to call the lab directly.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(f"http://127.0.0.1:{LAB_PORT}/api/ip-log", params={"limit": limit})
            return r.json()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Lab unreachable: {exc}")


@router.post("/ip-analysis/clear")
async def clear_ip_log():
    """Clear the lab's IP request log."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(f"http://127.0.0.1:{LAB_PORT}/api/ip-log/clear")
            return r.json()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Lab unreachable: {exc}")
