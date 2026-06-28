from datetime import datetime, timedelta, timezone
import jwt
import bcrypt
from fastapi import HTTPException, status
from src.config import settings
from src.users.service import load_users_from_file, save_users_to_file


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    payload = data.copy()
    delta = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + delta
    payload.update({"exp": expire})
    jwt_token = jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return jwt_token


def authenticate_user(email: str, password: str) -> dict | None:
    users = load_users_from_file()
    user = None
    for user_existing in users:
        if (
            user_existing["email"].lower() == email.lower()
            and not user_existing["is_deleted"]
        ):
            user = user_existing
            user_existing.update({"is_active": True})
            save_users_to_file(users)
            break

    if not user or user["is_deleted"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials: invalid email or deleted user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials: invalid password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is already logged in",
        )
    return user


def logout_user(user_id: int) -> dict:
    users = load_users_from_file()
    user_to_logout = None
    for user in users:
        if user["id"] == user_id and user["is_active"]:
            user_to_logout = user
            break
    if user_to_logout is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    user_to_logout["is_active"] = False
    save_users_to_file(users)
    return user_to_logout
