# 토스 로그인 샘플 (FastAPI)

토스 앱인토스 OAuth 로그인 연동 예제입니다.

## 앱인토스 vs 일반 토스 개발자 센터

이 프로젝트는 **앱인토스 (토스 미니앱)** 기준으로 구현되어 있습니다.

| 항목 | 앱인토스 | 일반 토스 개발자 센터 |
|------|----------|----------------------|
| API Base URL | `https://apps-in-toss-api.toss.im` | `https://toss.im` |
| 인증 방식 | `clientId` 만 사용 | `clientId` + `clientSecret` |
| 응답 데이터 | 복호화 키로 암호화된 데이터 복호화 | 평문 |
| 콘솔 | [앱인토스 콘솔](https://developers-apps-in-toss.toss.im) | [토스 개발자 센터](https://developers.toss.im) |

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

# OAuth 콜백 URL
REDIRECT_URI=http://localhost:8000/auth/toss/callback

# JWT 설정
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

| 환경 변수 | 설명 |
|----------|------|
| `TOSS_CLIENT_ID` | 앱인토스 콘솔에서 발급받은 클라이언트 ID |
| `TOSS_DECRYPTION_KEY` | 이메일로 발급받은 복호화 키 (Base64 인코딩) |
| `TOSS_BASIC_AUTH_CREDENTIAL` | 연결 끊기 콜백 인증용 credential |
| `REDIRECT_URI` | OAuth 콜백 URL (콘솔에 등록한 URL과 동일해야 함) |
| `JWT_SECRET_KEY` | 서비스 JWT 토큰 서명용 비밀키 (프로덕션에서는 반드시 변경) |

## 실행

```bash
uvicorn app.main:app --reload
```

서버가 실행되면 `http://localhost:8000/docs`에서 API 문서를 확인할 수 있습니다.

## API 엔드포인트

### 인증 플로우

| Method | 엔드포인트 | 설명 |
|--------|-----------|------|
| GET | `/auth/toss/authorize` | 토스 로그인 페이지로 리다이렉트 |
| GET | `/auth/toss/callback` | OAuth 콜백 (토스 로그인 → 서비스 JWT 발급) |
| POST | `/auth/toss/refresh` | 액세스 토큰 갱신 |
| GET | `/auth/toss/me` | 현재 로그인한 사용자 정보 |

### 로그아웃

| Method | 엔드포인트 | 설명 |
|--------|-----------|------|
| POST | `/auth/toss/logout` | 서비스 로그아웃 |
| POST | `/auth/toss/logout/toss` | 토스 서버 로그아웃 |

### 기타

| Method | 엔드포인트 | 설명 |
|--------|-----------|------|
| GET | `/auth/toss/userinfo` | 토스 사용자 정보 조회 (토스 토큰 필요) |
| POST/GET | `/auth/toss/unlink-callback` | 연결 끊기 콜백 (토스 → 서비스) |

## 로그인 플로우

```
1. 클라이언트 → GET /auth/toss/authorize
   └─→ 토스 로그인 페이지로 리다이렉트

2. 사용자가 토스앱에서 로그인 및 동의

3. 토스 → GET /auth/toss/callback?code=xxx
   ├─→ 토스 인가 코드로 토스 액세스 토큰 발급
   ├─→ 토스 액세스 토큰으로 사용자 정보 조회
   └─→ 서비스 JWT 토큰 발급 및 반환

4. 클라이언트 → GET /auth/toss/me (Authorization: Bearer {JWT})
   └─→ 현재 사용자 정보 반환

5. (액세스 토큰 만료 시) POST /auth/toss/refresh
   └─→ 새 액세스 토큰 발급

6. (로그아웃) POST /auth/toss/logout
   └─→ 세션 종료
```

## 토큰 구조

### 토스 토큰 vs 서비스 JWT 토큰

| 항목 | 토스 토큰 | 서비스 JWT 토큰 |
|------|----------|----------------|
| 용도 | 토스 API 호출 | 서비스 내부 인증 |
| 발급자 | 토스 | 서비스 자체 |
| 관리 | 토스 서버 | 서비스 서버 |
| 만료 | 토스 정책 | JWT 설정에 따름 |

### JWT 페이로드 구조

```json
{
  "sub": "userKey",           // 토스 사용자 고유 식별자
  "name": "홍길동",            // 사용자 이름
  "email": "user@example.com", // 사용자 이메일
  "exp": 1234567890,           // 만료 시간
  "iat": 1234567890,           // 발급 시간
  "type": "access"             // 토큰 타입 (access/refresh)
}
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
│   ├── config.py            # 환경변수 설정 (JWT 설정 포함)
│   ├── routers/
│   │   └── auth.py          # 토스 로그인 라우터
│   ├── services/
│   │   ├── toss_auth.py     # 토스 API 호출 서비스
│   │   └── jwt_handler.py   # JWT 토큰 생성/검증
│   ├── middleware/
│   │   └── auth.py          # 인증 미들웨어 (의존성 주입)
│   └── schemas/
│       └── auth.py          # Pydantic 모델
├── requirements.txt
└── README.md
```

## 주요 파일 설명

### `app/services/jwt_handler.py`
서비스 자체 JWT 토큰을 생성하고 검증합니다.
- `create_access_token()`: 액세스 토큰 생성
- `create_refresh_token()`: 리프레시 토큰 생성
- `verify_access_token()`: 액세스 토큰 검증
- `verify_refresh_token()`: 리프레시 토큰 검증

### `app/middleware/auth.py`
FastAPI 의존성 주입을 통한 인증 미들웨어입니다.
- `get_current_user()`: 필수 인증 (토큰 없으면 401)
- `get_current_user_optional()`: 선택 인증 (토큰 없으면 None)
- `RequiredUser`: 타입 힌트용 Annotated 타입

### `app/services/toss_auth.py`
토스 앱인토스 API를 호출하는 서비스입니다.
- `get_authorization_url()`: 인가 URL 생성
- `exchange_code_for_token()`: 인가 코드 → 토큰 발급
- `get_user_info()`: 사용자 정보 조회
- `_decrypt_data()`: 암호화된 응답 복호화 (앱인토스 전용)

## 참고 문서

- [토스 로그인 이해하기](https://developers-apps-in-toss.toss.im/login/intro.html)
- [콘솔 가이드](https://developers-apps-in-toss.toss.im/login/console.html)
- [개발하기](https://developers-apps-in-toss.toss.im/login/develop.html)
- [QA 진행하기](https://developers-apps-in-toss.toss.im/login/qa.html)


[x]
