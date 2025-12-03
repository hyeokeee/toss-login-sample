import base64
import json
from typing import Optional

import httpx
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.config import settings
from app.schemas.auth import TokenResponse, TossUserInfo


class TossAuthService:
    """토스 OAuth 인증 서비스"""

    def __init__(self):
        self.base_url = settings.toss_api_base_url
        self.client_id = settings.toss_client_id
        self.decryption_key = settings.toss_decryption_key

    async def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        인가 코드 요청 URL 생성

        Args:
            state: CSRF 방지를 위한 상태값 (선택)

        Returns:
            토스 로그인 페이지 URL
        """
        params = {
            "clientId": self.client_id,
            "redirectUri": settings.redirect_uri,
            "responseType": "code",
        }

        if state:
            params["state"] = state

        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.base_url}/api/v1/oauth/authorize?{query_string}"

    async def exchange_code_for_token(self, code: str) -> TokenResponse:
        """
        인가 코드로 액세스 토큰 발급

        Args:
            code: 인가 코드

        Returns:
            토큰 응답 (accessToken, refreshToken 등)

        Raises:
            httpx.HTTPStatusError: API 호출 실패 시
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/oauth/token",
                json={
                    "clientId": self.client_id,
                    "code": code,
                    "grantType": "authorization_code",
                },
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            data = response.json()

            # 응답 데이터가 암호화된 경우 복호화
            if "encryptedData" in data:
                decrypted_data = self._decrypt_data(data["encryptedData"])
                return TokenResponse(**decrypted_data)

            return TokenResponse(**data)

    async def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        """
        리프레시 토큰으로 액세스 토큰 갱신

        Args:
            refresh_token: 리프레시 토큰

        Returns:
            새로운 토큰 응답
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/oauth/token",
                json={
                    "clientId": self.client_id,
                    "refreshToken": refresh_token,
                    "grantType": "refresh_token",
                },
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            data = response.json()

            if "encryptedData" in data:
                decrypted_data = self._decrypt_data(data["encryptedData"])
                return TokenResponse(**decrypted_data)

            return TokenResponse(**data)

    async def get_user_info(self, access_token: str) -> TossUserInfo:
        """
        사용자 정보 조회

        Args:
            access_token: 액세스 토큰

        Returns:
            사용자 정보
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()

            data = response.json()

            # 응답 데이터가 암호화된 경우 복호화
            if "encryptedData" in data:
                decrypted_data = self._decrypt_data(data["encryptedData"])
                return TossUserInfo(**decrypted_data)

            return TossUserInfo(**data)

    async def logout(self, access_token: str) -> bool:
        """
        로그아웃 (토큰 무효화)

        Args:
            access_token: 액세스 토큰

        Returns:
            성공 여부
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/oauth/logout",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            return True

    def _decrypt_data(self, encrypted_data: str) -> dict:
        """
        토스 응답 데이터 복호화

        토스 로그인 응답은 AES-256-CBC로 암호화되어 있음

        Args:
            encrypted_data: Base64 인코딩된 암호화 데이터

        Returns:
            복호화된 JSON 데이터
        """
        if not self.decryption_key:
            raise ValueError("복호화 키가 설정되지 않았습니다.")

        # Base64 디코딩
        encrypted_bytes = base64.b64decode(encrypted_data)

        # IV는 암호화 데이터의 앞 16바이트
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]

        # 복호화 키 준비 (Base64 디코딩)
        key = base64.b64decode(self.decryption_key)

        # AES-256-CBC 복호화
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # PKCS7 패딩 제거
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return json.loads(data.decode("utf-8"))

    def verify_basic_auth(self, auth_header: str) -> bool:
        """
        Basic Auth 헤더 검증 (연결 끊기 콜백용)

        Args:
            auth_header: Authorization 헤더 값

        Returns:
            검증 성공 여부
        """
        if not auth_header.startswith("Basic "):
            return False

        try:
            encoded_credential = auth_header[6:]  # "Basic " 제거
            decoded_credential = base64.b64decode(encoded_credential).decode("utf-8")
            return decoded_credential == settings.toss_basic_auth_credential
        except Exception:
            return False


# 싱글톤 인스턴스
toss_auth_service = TossAuthService()

