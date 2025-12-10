"""
JWT 토큰 핸들러

서비스 자체 JWT 토큰을 생성하고 검증합니다.
토스 OAuth 토큰과는 별개로, 서비스 내부 인증에 사용됩니다.

왜 필요한가?
- 토스 액세스 토큰은 토스 API 호출에만 사용
- 서비스 자체 인증/인가를 위해 별도 JWT 토큰 필요
- 토스 토큰 만료와 무관하게 서비스 세션 관리 가능
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt

from app.config import settings


class JWTHandler:
    """JWT 토큰 생성 및 검증 핸들러"""

    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.jwt_access_token_expire_minutes
        self.refresh_token_expire_days = settings.jwt_refresh_token_expire_days

    def create_access_token(
        self,
        user_key: str,
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        JWT 액세스 토큰 생성

        Args:
            user_key: 토스 사용자 고유 식별자 (userKey)
            additional_claims: 추가 클레임 (이름, 이메일 등)

        Returns:
            JWT 액세스 토큰 문자열
        """
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=self.access_token_expire_minutes
        )

        payload = {
            "sub": user_key,  # subject: 사용자 식별자
            "exp": expire,  # expiration: 만료 시간
            "iat": datetime.now(timezone.utc),  # issued at: 발급 시간
            "type": "access",  # 토큰 타입
        }

        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_key: str) -> str:
        """
        JWT 리프레시 토큰 생성

        리프레시 토큰은 액세스 토큰 갱신에만 사용되므로
        최소한의 정보만 포함합니다.

        Args:
            user_key: 토스 사용자 고유 식별자

        Returns:
            JWT 리프레시 토큰 문자열
        """
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.refresh_token_expire_days
        )

        payload = {
            "sub": user_key,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh",
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> dict[str, Any]:
        """
        토큰 검증 및 페이로드 추출

        Args:
            token: JWT 토큰 문자열

        Returns:
            토큰 페이로드 딕셔너리

        Raises:
            JWTError: 토큰이 유효하지 않거나 만료된 경우
        """
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """
        액세스 토큰 검증

        Args:
            token: JWT 액세스 토큰

        Returns:
            토큰 페이로드

        Raises:
            JWTError: 토큰이 유효하지 않거나 타입이 다른 경우
        """
        payload = self.verify_token(token)

        if payload.get("type") != "access":
            raise JWTError("액세스 토큰이 아닙니다.")

        return payload

    def verify_refresh_token(self, token: str) -> dict[str, Any]:
        """
        리프레시 토큰 검증

        Args:
            token: JWT 리프레시 토큰

        Returns:
            토큰 페이로드

        Raises:
            JWTError: 토큰이 유효하지 않거나 타입이 다른 경우
        """
        payload = self.verify_token(token)

        if payload.get("type") != "refresh":
            raise JWTError("리프레시 토큰이 아닙니다.")

        return payload

    def get_user_key_from_token(self, token: str) -> str:
        """
        토큰에서 사용자 키 추출

        Args:
            token: JWT 토큰

        Returns:
            사용자 키 (userKey)

        Raises:
            JWTError: 토큰이 유효하지 않은 경우
        """
        payload = self.verify_token(token)
        return payload.get("sub", "")


# 싱글톤 인스턴스
jwt_handler = JWTHandler()




