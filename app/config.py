from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """토스 로그인 설정"""

    # 토스 앱인토스 API 설정
    # 앱인토스는 client_secret 없이 clientId만 사용 (일반 토스 개발자 센터와 다름)
    toss_client_id: str = ""
    toss_decryption_key: str = ""  # 앱인토스 콘솔에서 이메일로 발급받은 복호화 키
    toss_basic_auth_credential: str = ""  # 연결 끊기 콜백 인증용

    # 토스 API Base URL
    # 앱인토스: https://apps-in-toss-api.toss.im
    # 일반 토스: https://toss.im (사용하지 않음)
    toss_api_base_url: str = "https://apps-in-toss-api.toss.im"

    # OAuth 콜백 URL (앱인토스 콘솔에 등록한 URL과 동일해야 함)
    redirect_uri: str = "http://localhost:8000/auth/toss/callback"

    # JWT 설정
    jwt_secret_key: str = "your-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

