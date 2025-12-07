"""
인증 미들웨어 (의존성 주입)

FastAPI의 Depends를 사용하여 인증이 필요한 엔드포인트에서
현재 로그인한 사용자 정보를 주입합니다.

사용 예시:
    @router.get("/me")
    async def get_me(current_user: CurrentUser = Depends(get_current_user)):
        return current_user
"""

from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from app.schemas.auth import CurrentUser
from app.services.jwt_handler import jwt_handler

# HTTPBearer 스킴 정의
# auto_error=True: 토큰이 없으면 자동으로 401 에러
security = HTTPBearer(auto_error=True)

# auto_error=False 버전: 토큰이 없어도 에러 없이 None 반환
security_optional = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> CurrentUser:
    """
    현재 로그인한 사용자 조회 (필수)

    JWT 액세스 토큰을 검증하고 사용자 정보를 반환합니다.
    토큰이 없거나 유효하지 않으면 401 에러를 발생시킵니다.

    Args:
        credentials: Bearer 토큰 (HTTPBearer에서 자동 추출)

    Returns:
        현재 사용자 정보

    Raises:
        HTTPException: 인증 실패 시 401 에러
    """
    token = credentials.credentials

    try:
        # JWT 토큰 검증
        payload = jwt_handler.verify_access_token(token)

        user_key = payload.get("sub")
        if not user_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "errorCode": "INVALID_TOKEN",
                    "errorMessage": "토큰에 사용자 정보가 없습니다.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 토큰에서 사용자 정보 추출
        return CurrentUser(
            user_key=user_key,
            name=payload.get("name"),
            email=payload.get("email"),
        )

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "errorCode": "INVALID_TOKEN",
                "errorMessage": f"토큰 검증에 실패했습니다: {str(e)}",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional),
) -> Optional[CurrentUser]:
    """
    현재 로그인한 사용자 조회 (선택)

    토큰이 있으면 검증하고 사용자 정보를 반환합니다.
    토큰이 없으면 None을 반환합니다.
    토큰이 있지만 유효하지 않으면 401 에러를 발생시킵니다.

    Args:
        credentials: Bearer 토큰 (없을 수 있음)

    Returns:
        현재 사용자 정보 또는 None

    Raises:
        HTTPException: 토큰이 있지만 유효하지 않은 경우 401 에러
    """
    if not credentials:
        return None

    return await get_current_user(credentials)


# 타입 힌트용 Annotated 타입
# 사용 예시: current_user: RequiredUser
RequiredUser = Annotated[CurrentUser, Depends(get_current_user)]
OptionalUser = Annotated[Optional[CurrentUser], Depends(get_current_user_optional)]

