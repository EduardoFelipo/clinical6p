"""
Rotas de Autenticação
- Login (email para funcionários, CPF para pacientes)
- Recuperação de senha (esqueci minha senha)
"""

import secrets
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from pydantic import BaseModel

from app.database import AsyncSession, get_db
from app.models import User, Patient, PasswordResetToken
from app.auth import verify_password, get_password_hash, create_access_token
from app.config import settings
from app.schemas import ForgotPasswordRequest, ResetPasswordRequest
from app.email_utils import send_reset_password_link_email
from app.limiter import limiter


router = APIRouter(prefix="/api", tags=["Autenticação"])
logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════
# SCHEMAS LOCAIS
# ═════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    """
    Corpo JSON esperado para a requisição de login.
    """
    email: str
    password: str


# ═════════════════════════════════════════════════════════════════════
# ENDPOINTS DE AUTENTICAÇÃO
# ═════════════════════════════════════════════════════════════════════

def _set_auth_cookie(response: Response, token: str, expire_minutes: int) -> None:
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=expire_minutes * 60,
    )


@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, response: Response, body: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    try:
        email_or_cpf = body.email.strip()
        password = body.password.strip()

        # --- Tenta login como funcionário (tabela Users) ---
        stmt_user = select(User).where(User.email == email_or_cpf)
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if user:
            if not user.is_active:
                raise HTTPException(status_code=403, detail="Usuário inativo. Contate o administrador.")
            if not verify_password(password, user.hashed_password):
                raise HTTPException(status_code=401, detail="Senha incorreta.")
            token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
            _set_auth_cookie(response, token, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            return {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "photo": user.photo,
            }

        # --- Tenta login como paciente (tabela Patients) ---
        stmt_patient = select(Patient).where(Patient.cpf == email_or_cpf)
        result_patient = await db.execute(stmt_patient)
        patient = result_patient.scalars().first()

        if patient and patient.hashed_password:
            if patient.status != "Ativo":
                raise HTTPException(status_code=403, detail="Paciente inativo. Contate a clínica.")
            if not verify_password(password, patient.hashed_password):
                raise HTTPException(status_code=401, detail="Senha incorreta.")
            token = create_access_token({"sub": str(patient.id), "email": patient.cpf, "role": "patient"})
            _set_auth_cookie(response, token, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            return {
                "id": patient.id,
                "email": patient.cpf,
                "full_name": patient.name,
                "role": "patient",
            }

        raise HTTPException(status_code=404, detail="E-mail ou CPF não encontrado no sistema.")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro inesperado no login: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail="Serviço temporariamente indisponível.")


@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(key="access_token", httponly=True, samesite="lax")
    return {"message": "Logout realizado com sucesso."}


@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)) -> dict:
    email = body.email.strip()
    _GENERIC_RESPONSE = {"message": "Se esse e-mail estiver cadastrado, você receberá um link de redefinição em instantes."}

    # Verifica se pertence a um funcionário ou paciente
    result_user = await db.execute(select(User).where(User.email == email))
    user = result_user.scalars().first()

    result_patient = await db.execute(select(Patient).where(Patient.email == email))
    patient = result_patient.scalars().first()

    if not user and not patient:
        # Retorna a mesma resposta genérica — não revela se o e-mail existe
        return _GENERIC_RESPONSE

    # Gera token seguro e persiste com expiração de 1 hora
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)

    db.add(PasswordResetToken(token=token, email=email, expires_at=expires_at))
    await db.flush()  # persiste o token sem commit ainda

    reset_link = f"{settings.APP_BASE_URL}/reset-password?token={token}"

    email_status = await send_reset_password_link_email(db=db, email=email, reset_link=reset_link)
    if email_status == "not_configured":
        await db.rollback()
        raise HTTPException(
            status_code=503,
            detail="O sistema de e-mail não está configurado. Entre em contato com o administrador."
        )
    if email_status == "error":
        await db.rollback()
        raise HTTPException(
            status_code=502,
            detail="Falha ao enviar o e-mail. Verifique as configurações de SMTP no painel e tente novamente."
        )

    await db.commit()
    return _GENERIC_RESPONSE


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, body: ResetPasswordRequest, db: AsyncSession = Depends(get_db)) -> dict:
    if len(body.new_password) < 8:
        raise HTTPException(status_code=422, detail="A nova senha deve ter pelo menos 8 caracteres.")

    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token == body.token)
    )
    reset_token = result.scalars().first()

    if not reset_token:
        raise HTTPException(status_code=400, detail="Link inválido ou já utilizado.")
    if reset_token.used:
        raise HTTPException(status_code=400, detail="Este link já foi utilizado. Solicite um novo.")
    if datetime.now(timezone.utc).replace(tzinfo=None) > reset_token.expires_at:
        raise HTTPException(status_code=400, detail="Este link expirou. Solicite um novo.")

    email = reset_token.email
    new_hash = get_password_hash(body.new_password)

    result_user = await db.execute(select(User).where(User.email == email))
    user = result_user.scalars().first()
    if user:
        user.hashed_password = new_hash
    else:
        result_patient = await db.execute(select(Patient).where(Patient.email == email))
        patient = result_patient.scalars().first()
        if patient:
            patient.hashed_password = new_hash
        else:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    reset_token.used = True
    await db.commit()

    return {"message": "Senha redefinida com sucesso. Você já pode fazer login."}
