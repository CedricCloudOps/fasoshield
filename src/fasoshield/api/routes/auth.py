"""Analyst authentication and account administration.

Login is deliberately uniform: wrong password, unknown user and disabled
account all return the same 401, so the endpoint cannot be used to enumerate
console operators.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ...accounts import (
    AccountError,
    authenticate,
    close_session,
    create_account,
    list_accounts,
    open_session,
    recent_audit,
    record_audit,
    set_active,
    set_password,
    set_role,
)
from ...config import settings
from ...security import PasswordPolicyError, Role, parse_role
from ..deps import (
    AdminDep,
    Analyst,
    ViewerDep,
    client_ip,
    current_analyst,
    get_db,
)
from ..schemas import (
    AccountCreate,
    AccountOut,
    AccountUpdate,
    AuditEventOut,
    LoginRequest,
    SessionInfo,
)

router = APIRouter(tags=["auth"])


@router.post("/v1/auth/login", response_model=SessionInfo)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> SessionInfo:
    ip = client_ip(request)
    account = authenticate(db, payload.username, payload.password)
    if account is None:
        record_audit(
            db, actor=payload.username[:64], action="auth.login_failed", client_ip=ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    token = open_session(db, account.username, client_ip=ip)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,  # never readable from JavaScript
        secure=settings.session_cookie_secure,
        samesite="lax",  # blocks cross-site POSTs while keeping normal navigation
        path="/",
    )
    record_audit(db, actor=account.username, action="auth.login", client_ip=ip)
    return SessionInfo(
        username=account.username,
        display_name=account.display_name,
        role=account.role,
        authenticated=True,
    )


@router.post("/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    token = request.cookies.get(settings.session_cookie_name, "")
    if token:
        close_session(db, token)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/v1/auth/me", response_model=SessionInfo)
def whoami(analyst: Analyst | None = Depends(current_analyst)) -> SessionInfo:
    """Session probe used by the console to decide between the dashboard and
    the login form. Always 200, so an anonymous visitor gets no error noise."""
    if analyst is None:
        return SessionInfo(username="", display_name="", role="", authenticated=False)
    return SessionInfo(
        username=analyst.username,
        display_name=analyst.display_name,
        role=analyst.role.value,
        authenticated=True,
    )


# -- account administration ------------------------------------------------


@router.get("/v1/accounts", response_model=list[AccountOut], dependencies=[AdminDep])
def accounts(db: Session = Depends(get_db)) -> list[AccountOut]:
    return [AccountOut.model_validate(a, from_attributes=True) for a in list_accounts(db)]


@router.post(
    "/v1/accounts",
    response_model=AccountOut,
    status_code=status.HTTP_201_CREATED,
)
def add_account(
    payload: AccountCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: Analyst = AdminDep,
) -> AccountOut:
    try:
        account = create_account(
            db,
            username=payload.username,
            password=payload.password,
            role=parse_role(payload.role, default=Role.VIEWER),
            display_name=payload.display_name,
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except AccountError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    record_audit(
        db,
        actor=admin.username,
        action="account.create",
        target=account.username,
        detail={"role": account.role},
        client_ip=client_ip(request),
    )
    return AccountOut.model_validate(account, from_attributes=True)


@router.patch("/v1/accounts/{username}", response_model=AccountOut)
def update_account(
    username: str,
    payload: AccountUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: Analyst = AdminDep,
) -> AccountOut:
    changes: dict[str, object] = {}
    try:
        if payload.password is not None:
            set_password(db, username, payload.password)
            # The audit trail records that a reset happened, never the value.
            changes["password_reset"] = True
        if payload.role is not None:
            set_role(db, username, parse_role(payload.role, default=Role.VIEWER))
            changes["role"] = payload.role
        if payload.is_active is not None:
            if not payload.is_active and username.strip().lower() == admin.username:
                # Losing the last admin would lock the console permanently.
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An administrator cannot disable their own account",
                )
            set_active(db, username, payload.is_active)
            changes["is_active"] = payload.is_active
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except AccountError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if changes:
        record_audit(
            db,
            actor=admin.username,
            action="account.update",
            target=username,
            detail=changes,
            client_ip=client_ip(request),
        )
    from ...db.models import AnalystAccount

    return AccountOut.model_validate(
        db.get(AnalystAccount, username.strip().lower()), from_attributes=True
    )


@router.get("/v1/audit", response_model=list[AuditEventOut], dependencies=[ViewerDep])
def audit_trail(limit: int = 50, db: Session = Depends(get_db)) -> list[AuditEventOut]:
    limit = max(1, min(limit, 500))
    return [
        AuditEventOut.model_validate(event, from_attributes=True)
        for event in recent_audit(db, limit=limit)
    ]
