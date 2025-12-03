# 토스 로그인 샘플 (FastAPI)

토스 앱인토스 OAuth 로그인 연동 예제입니다.

## 사전 준비

토스 로그인을 사용하려면 **앱인토스 콘솔**에서 다음 설정을 완료해야 합니다:

1. **약관 동의** - 대표관리자 계정으로 진행
2. **동의 항목 설정** - USER_NAME, USER_EMAIL, USER_GENDER 등
3. **약관 등록** - 서비스 이용약관, 개인정보 수집·이용 동의 등
4. **연결 끊기 콜백 URL** - 선택 항목 사용 시 필수
5. **복호화 키 발급** - 이메일로 받기

자세한 내용은 [앱인토스 개발자 문서](https://developers-apps-in-toss.toss.im/login/intro.html)를 참고하세요.

## 설치

```bash
# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

## 환경 변수 설정

프로젝트 루트에 `.env` 파일을 생성하고 다음 값을 설정합니다:

```env
# 토스 앱인토스 설정
TOSS_CLIENT_ID=your_client_id_here
TOSS_DECRYPTION_KEY=your_decryption_key_here
TOSS_BASIC_AUTH_CREDENTIAL=your_basic_auth_credential_here

# 서버 설정
REDIRECT_URI=http://localhost:8000/auth/toss/callback
```

| 환경 변수 | 설명 |
|----------|------|
| `TOSS_CLIENT_ID` | 앱인토스 콘솔에서 발급받은 클라이언트 ID |
| `TOSS_DECRYPTION_KEY` | 이메일로 발급받은 복호화 키 (Base64 인코딩) |
| `TOSS_BASIC_AUTH_CREDENTIAL` | 연결 끊기 콜백 인증용 credential |
| `REDIRECT_URI` | OAuth 콜백 URL (콘솔에 등록한 URL과 동일해야 함) |

## 실행

```bash
uvicorn app.main:app --reload
```

서버가 실행되면 `http://localhost:8000/docs`에서 API 문서를 확인할 수 있습니다.

## API 엔드포인트

| Method | 엔드포인트 | 설명 |
|--------|-----------|------|
| GET | `/auth/toss/authorize` | 토스 로그인 페이지로 리다이렉트 |
| GET | `/auth/toss/callback` | OAuth 콜백 (인가 코드 → 토큰 발급) |
| GET | `/auth/toss/userinfo` | 사용자 정보 조회 |
| POST | `/auth/toss/logout` | 로그아웃 |
| POST | `/auth/toss/unlink-callback` | 연결 끊기 콜백 (토스 → 서비스) |

## 로그인 플로우

```
1. 클라이언트 → GET /auth/toss/authorize
   └─→ 토스 로그인 페이지로 리다이렉트

2. 사용자가 토스앱에서 로그인 및 동의

3. 토스 → GET /auth/toss/callback?code=xxx
   └─→ 인가 코드로 액세스 토큰 발급
   └─→ 토큰 응답 반환

4. 클라이언트 → GET /auth/toss/userinfo
   └─→ 사용자 정보 조회

5. (선택) 클라이언트 → POST /auth/toss/logout
   └─→ 토큰 무효화 및 세션 종료
```

## 연결 끊기 콜백

사용자가 토스앱에서 연결을 끊으면 등록된 콜백 URL로 이벤트가 전송됩니다.

| referrer | 설명 |
|----------|------|
| `UNLINK` | 사용자가 직접 연결 끊기 |
| `WITHDRAWAL_TERMS` | 약관 동의 철회 |
| `WITHDRAWAL_TOSS` | 토스 회원 탈퇴 |

## 프로젝트 구조

```
toss-login-sample/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI 앱 엔트리포인트
│   ├── config.py            # 환경변수 설정
│   ├── routers/
│   │   └── auth.py          # 토스 로그인 라우터
│   ├── services/
│   │   └── toss_auth.py     # 토스 API 호출 서비스
│   └── schemas/
│       └── auth.py          # Pydantic 모델
├── requirements.txt
└── README.md
```

## 참고 문서

- [토스 로그인 이해하기](https://developers-apps-in-toss.toss.im/login/intro.html)
- [콘솔 가이드](https://developers-apps-in-toss.toss.im/login/console.html)
- [개발하기](https://developers-apps-in-toss.toss.im/login/develop.html)
- [QA 진행하기](https://developers-apps-in-toss.toss.im/login/qa.html)
