from fastapi import FastAPI

from app.routers import auth

app = FastAPI(
    title="토스 로그인 샘플",
    description="토스 앱인토스 OAuth 로그인 연동 예제",
    version="1.0.0",
)

# 라우터 등록
app.include_router(auth.router, prefix="/auth/toss", tags=["토스 로그인"])


@app.get("/", tags=["헬스체크"])
async def root():
    """서버 상태 확인"""
    return {"status": "ok", "message": "토스 로그인 샘플 서버가 실행 중입니다."}

