"""Shared FastAPI dependencies: engine singleton, DB session, agent and
analyst authentication.

Two separate identities coexist on this API:

- **agents** — mobile devices, authenticated by a shared API key, allowed only
  on the reputation / signature-update / telemetry endpoints;
- **analysts** — accountable people, authenticated by a session cookie (or by
  an SSO gateway), holding a role that governs the signature workflow and the
  intelligence exports.

An agent key never grants analyst rights, and vice versa.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Request, status

from ..accounts import resolve_session
from ..config import settings
from ..db.session import get_session
from ..engine.hashdb import HashDB
from ..engine.scanner import ScanEngine
from ..engine.yara_scanner import YaraScanner
from ..security import Role, parse_role
from ..storage import QuarantineStore, open_quarantine


@lru_cache(maxsize=1)
def get_hashdb() -> HashDB:
    return HashDB(settings.hashdb_path)


@lru_cache(maxsize=1)
def get_scan_engine() -> ScanEngine:
    return ScanEngine(hashdb=get_hashdb(), yara_scanner=YaraScanner(settings.yara_dir))


@lru_cache(maxsize=1)
def get_quarantine() -> QuarantineStore:
    return open_quarantine(settings.effective_quarantine_url)


def get_db():
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def client_ip(request: Request) -> str | None:
    """Client address, honouring X-Forwarded-For only for the number of proxy
    hops the deployment declares. Trusting the whole header would let any
    caller forge its own address in the audit trail."""
    hops = settings.trusted_proxy_count
    if hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(chain) >= hops:
            return chain[-hops]
    return request.client.host if request.client else None


# -- agent authentication --------------------------------------------------


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Agent authentication. When no key is configured the API runs in open
    dev mode; production deployments must set FASOSHIELD_API_KEYS."""
    keys = settings.api_key_set
    if not keys:
        return
    if x_api_key not in keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


AuthDep = Depends(require_api_key)


# -- analyst authentication ------------------------------------------------


class Analyst:
    """The authenticated console operator for the current request."""

    def __init__(self, username: str, display_name: str, role: Role, via: str) -> None:
        self.username = username
        self.display_name = display_name
        self.role = role
        self.via = via  # session | sso

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Analyst({self.username!r}, role={self.role.value})"


def current_analyst(request: Request, db=Depends(get_db)) -> Analyst | None:
    """Resolve the analyst behind the request, or None when unauthenticated."""
    if settings.sso_user_header:
        # An authenticating reverse proxy (OIDC/SAML gateway) vouches for the
        # user. Only safe when the API is unreachable except through it —
        # otherwise anyone could send the header. See docs/DEPLOYMENT.md.
        username = request.headers.get(settings.sso_user_header, "").strip().lower()
        if username:
            raw_role = (
                request.headers.get(settings.sso_role_header, "")
                if settings.sso_role_header
                else ""
            )
            role = parse_role(raw_role or settings.sso_default_role)
            return Analyst(username, username, role, via="sso")

    token = request.cookies.get(settings.session_cookie_name, "")
    account = resolve_session(db, token)
    if account is None:
        return None
    return Analyst(
        account.username,
        account.display_name,
        parse_role(account.role),
        via="session",
    )


def require_analyst(minimum: Role = Role.VIEWER):
    """Dependency factory enforcing a minimum console role."""

    def dependency(analyst: Analyst | None = Depends(current_analyst)) -> Analyst:
        if analyst is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Analyst authentication required",
                headers={"WWW-Authenticate": "Cookie"},
            )
        if not analyst.role.covers(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{minimum.value}' or higher required",
            )
        return analyst

    return dependency


ViewerDep = Depends(require_analyst(Role.VIEWER))
AnalystDep = Depends(require_analyst(Role.ANALYST))
AdminDep = Depends(require_analyst(Role.ADMIN))
