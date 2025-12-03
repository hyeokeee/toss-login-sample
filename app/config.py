from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """토스 로그인 설정"""

    # 토스 앱인토스 API 설정
    toss_client_id: str = ""
    toss_decryption_key: str = ""
    toss_basic_auth_credential: str = ""

    # 토스 API Base URL
    toss_api_base_url: str = "https://apps-in-toss-api.toss.im"

    # OAuth 콜백 URL
    redirect_uri: str = "http://localhost:8000/auth/toss/callback"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

