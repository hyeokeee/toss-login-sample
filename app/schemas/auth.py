from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Gender(str, Enum):
    """성별"""

    MALE = "MALE"
    FEMALE = "FEMALE"


class Nationality(str, Enum):
    """국적"""

    DOMESTIC = "DOMESTIC"
    FOREIGN = "FOREIGN"


class UnlinkReferrer(str, Enum):
    """연결 끊기 이벤트 경로"""

    UNLINK = "UNLINK"  # 사용자가 앱에서 직접 연결 끊기
    WITHDRAWAL_TERMS = "WITHDRAWAL_TERMS"  # 로그인 서비스 약관 철회
    WITHDRAWAL_TOSS = "WITHDRAWAL_TOSS"  # 토스 회원 탈퇴


# === 토큰 관련 스키마 ===


class TokenResponse(BaseModel):
    """토스 OAuth 토큰 응답"""

    access_token: str = Field(..., alias="accessToken", description="액세스 토큰")
    refresh_token: str = Field(..., alias="refreshToken", description="리프레시 토큰")
    token_type: str = Field(default="Bearer", alias="tokenType", description="토큰 타입")
    expires_in: int = Field(..., alias="expiresIn", description="액세스 토큰 만료 시간(초)")

    class Config:
        populate_by_name = True


class TokenRequest(BaseModel):
    """토큰 발급 요청"""

    code: str = Field(..., description="인가 코드")


# === 사용자 정보 스키마 ===


class TossUserInfo(BaseModel):
    """토스 사용자 정보"""

    user_key: str = Field(..., alias="userKey", description="사용자 고유 식별자")
    name: Optional[str] = Field(None, alias="name", description="이름")
    email: Optional[str] = Field(None, alias="email", description="이메일")
    gender: Optional[Gender] = Field(None, alias="gender", description="성별")
    birthday: Optional[str] = Field(None, alias="birthday", description="생년월일 (YYYYMMDD)")
    nationality: Optional[Nationality] = Field(None, alias="nationality", description="국적")
    phone: Optional[str] = Field(None, alias="phone", description="전화번호")
    ci: Optional[str] = Field(None, alias="ci", description="CI (Connection Information)")

    class Config:
        populate_by_name = True


class UserInfoResponse(BaseModel):
    """사용자 정보 응답"""

    success: bool = True
    user: TossUserInfo


# === 연결 끊기 콜백 스키마 ===


class UnlinkCallbackRequest(BaseModel):
    """연결 끊기 콜백 요청"""

    user_key: str = Field(..., alias="userKey", description="사용자 고유 식별자")
    referrer: UnlinkReferrer = Field(..., description="연결 끊기 이벤트 경로")

    class Config:
        populate_by_name = True


class UnlinkCallbackResponse(BaseModel):
    """연결 끊기 콜백 응답"""

    success: bool = True
    message: str = "연결 끊기 처리 완료"


# === 공통 응답 스키마 ===


class ErrorResponse(BaseModel):
    """에러 응답"""

    success: bool = False
    error_code: str = Field(..., alias="errorCode", description="에러 코드")
    error_message: str = Field(..., alias="errorMessage", description="에러 메시지")

    class Config:
        populate_by_name = True


class LogoutResponse(BaseModel):
    """로그아웃 응답"""

    success: bool = True
    message: str = "로그아웃 완료"

