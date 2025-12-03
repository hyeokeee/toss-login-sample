import secrets
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from app.schemas.auth import (
    ErrorResponse,
    LogoutResponse,
    TokenResponse,
    UnlinkCallbackRequest,
    UnlinkCallbackResponse,
    UnlinkReferrer,
    UserInfoResponse,
)
from app.services.toss_auth import toss_auth_service

router = APIRouter()


@router.get(
    "/authorize",
    summary="토스 로그인 인가 요청",
    description="토스 로그인 페이지로 리다이렉트합니다. 사용자가 동의하면 콜백 URL로 인가 코드가 전달됩니다.",
)
async def authorize(
    state: Optional[str] = Query(
        default=None,
        description="CSRF 방지를 위한 상태값. 미입력 시 자동 생성됩니다.",
    ),
):
    """
    토스 로그인 인가 코드 요청

    1. 토스 로그인 페이지로 리다이렉트
    2. 사용자가 로그인 및 동의
    3. 콜백 URL로 인가 코드 전달
    """
    # state가 없으면 자동 생성 (CSRF 방지)
    if not state:
        state = secrets.token_urlsafe(32)

    authorization_url = await toss_auth_service.get_authorization_url(state=state)
    return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)


@router.get(
    "/callback",
    response_model=TokenResponse,
    responses={
        400: {"model": ErrorResponse, "description": "인가 코드 없음 또는 에러"},
        500: {"model": ErrorResponse, "description": "토큰 발급 실패"},
    },
    summary="토스 로그인 콜백",
    description="토스에서 리다이렉트된 인가 코드를 받아 액세스 토큰을 발급합니다.",
)
async def callback(
    code: Optional[str] = Query(default=None, description="인가 코드"),
    state: Optional[str] = Query(default=None, description="상태값 (CSRF 검증용)"),
    error: Optional[str] = Query(default=None, description="에러 코드"),
    error_description: Optional[str] = Query(
        default=None, alias="errorDescription", description="에러 설명"
    ),
):
    """
    토스 로그인 콜백 처리

    토스에서 리다이렉트된 요청을 처리하여 액세스 토큰을 발급합니다.
    실제 서비스에서는 발급된 토큰을 안전하게 저장하고 세션을 생성해야 합니다.
    """
    # 에러 응답 처리
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "errorCode": error,
                "errorMessage": error_description or "토스 로그인 중 에러가 발생했습니다.",
            },
        )

    # 인가 코드 검증
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "errorCode": "MISSING_CODE",
                "errorMessage": "인가 코드가 없습니다.",
            },
        )

    # TODO: state 값 검증 (세션에 저장된 값과 비교)
    # 실제 서비스에서는 authorize에서 생성한 state와 비교해야 합니다.

    try:
        # 인가 코드로 토큰 발급
        token_response = await toss_auth_service.exchange_code_for_token(code)

        # TODO: 토큰을 안전하게 저장 (DB, Redis 등)
        # TODO: 사용자 세션 생성

        return token_response

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "errorCode": "TOKEN_EXCHANGE_FAILED",
                "errorMessage": f"토큰 발급에 실패했습니다: {str(e)}",
            },
        )


@router.get(
    "/userinfo",
    response_model=UserInfoResponse,
    responses={
        401: {"model": ErrorResponse, "description": "인증 필요"},
        500: {"model": ErrorResponse, "description": "사용자 정보 조회 실패"},
    },
    summary="사용자 정보 조회",
    description="액세스 토큰을 사용하여 토스 사용자 정보를 조회합니다.",
)
async def get_user_info(
    authorization: str = Header(..., description="Bearer 액세스 토큰"),
):
    """
    토스 사용자 정보 조회

    동의 항목에 따라 이름, 이메일, 성별, 생일, 국적, 전화번호, CI 등을 반환합니다.
    """
    # Bearer 토큰 추출
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "errorCode": "INVALID_TOKEN_FORMAT",
                "errorMessage": "Bearer 토큰 형식이 아닙니다.",
            },
        )

    access_token = authorization[7:]  # "Bearer " 제거

    try:
        user_info = await toss_auth_service.get_user_info(access_token)
        return UserInfoResponse(success=True, user=user_info)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "errorCode": "USER_INFO_FAILED",
                "errorMessage": f"사용자 정보 조회에 실패했습니다: {str(e)}",
            },
        )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    responses={
        401: {"model": ErrorResponse, "description": "인증 필요"},
        500: {"model": ErrorResponse, "description": "로그아웃 실패"},
    },
    summary="로그아웃",
    description="토스 로그인 세션을 종료하고 토큰을 무효화합니다.",
)
async def logout(
    authorization: str = Header(..., description="Bearer 액세스 토큰"),
):
    """
    로그아웃 처리

    토스 서버에 토큰 무효화를 요청하고 서비스 세션을 종료합니다.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "errorCode": "INVALID_TOKEN_FORMAT",
                "errorMessage": "Bearer 토큰 형식이 아닙니다.",
            },
        )

    access_token = authorization[7:]

    try:
        await toss_auth_service.logout(access_token)

        # TODO: 서비스 세션 삭제
        # TODO: 저장된 토큰 삭제

        return LogoutResponse(success=True, message="로그아웃이 완료되었습니다.")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "errorCode": "LOGOUT_FAILED",
                "errorMessage": f"로그아웃에 실패했습니다: {str(e)}",
            },
        )


@router.post(
    "/unlink-callback",
    response_model=UnlinkCallbackResponse,
    responses={
        401: {"model": ErrorResponse, "description": "인증 실패"},
        500: {"model": ErrorResponse, "description": "처리 실패"},
    },
    summary="연결 끊기 콜백",
    description="사용자가 토스앱에서 로그인 연결을 해제할 때 호출됩니다.",
)
async def unlink_callback(
    request: UnlinkCallbackRequest,
    authorization: str = Header(..., description="Basic Auth 헤더"),
):
    """
    연결 끊기 콜백 처리

    토스앱에서 사용자가 연결을 끊으면 이 엔드포인트로 알림이 옵니다.

    referrer 값에 따른 처리:
    - UNLINK: 사용자가 직접 연결 끊기 → 로그아웃 처리 필요
    - WITHDRAWAL_TERMS: 약관 동의 철회
    - WITHDRAWAL_TOSS: 토스 회원 탈퇴
    """
    # Basic Auth 검증
    if not toss_auth_service.verify_basic_auth(authorization):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "errorCode": "INVALID_AUTH",
                "errorMessage": "인증에 실패했습니다.",
            },
        )

    user_key = request.user_key
    referrer = request.referrer

    try:
        # referrer에 따른 처리
        if referrer == UnlinkReferrer.UNLINK:
            # 사용자가 직접 연결을 끊은 경우
            # TODO: 해당 사용자의 세션 무효화
            # TODO: 저장된 토큰 삭제
            message = f"사용자 {user_key}의 연결이 해제되었습니다. 로그아웃 처리가 필요합니다."

        elif referrer == UnlinkReferrer.WITHDRAWAL_TERMS:
            # 약관 동의 철회
            # TODO: 약관 동의 정보 삭제
            message = f"사용자 {user_key}의 약관 동의가 철회되었습니다."

        elif referrer == UnlinkReferrer.WITHDRAWAL_TOSS:
            # 토스 회원 탈퇴
            # TODO: 사용자 계정 비활성화 또는 삭제 처리
            message = f"사용자 {user_key}가 토스 회원을 탈퇴했습니다."

        else:
            message = f"알 수 없는 연결 끊기 이벤트: {referrer}"

        return UnlinkCallbackResponse(success=True, message=message)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "errorCode": "UNLINK_CALLBACK_FAILED",
                "errorMessage": f"연결 끊기 처리에 실패했습니다: {str(e)}",
            },
        )


@router.get(
    "/unlink-callback",
    response_model=UnlinkCallbackResponse,
    responses={
        401: {"model": ErrorResponse, "description": "인증 실패"},
    },
    summary="연결 끊기 콜백 (GET)",
    description="GET 방식의 연결 끊기 콜백입니다.",
)
async def unlink_callback_get(
    user_key: str = Query(..., alias="userKey", description="사용자 고유 식별자"),
    referrer: UnlinkReferrer = Query(..., description="연결 끊기 이벤트 경로"),
    authorization: str = Header(..., description="Basic Auth 헤더"),
):
    """
    연결 끊기 콜백 (GET 방식)

    콘솔에서 GET 방식을 선택한 경우 이 엔드포인트가 호출됩니다.
    """
    # Basic Auth 검증
    if not toss_auth_service.verify_basic_auth(authorization):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "errorCode": "INVALID_AUTH",
                "errorMessage": "인증에 실패했습니다.",
            },
        )

    # POST 핸들러와 동일한 로직 사용
    request = UnlinkCallbackRequest(userKey=user_key, referrer=referrer)

    if referrer == UnlinkReferrer.UNLINK:
        message = f"사용자 {user_key}의 연결이 해제되었습니다."
    elif referrer == UnlinkReferrer.WITHDRAWAL_TERMS:
        message = f"사용자 {user_key}의 약관 동의가 철회되었습니다."
    elif referrer == UnlinkReferrer.WITHDRAWAL_TOSS:
        message = f"사용자 {user_key}가 토스 회원을 탈퇴했습니다."
    else:
        message = f"연결 끊기 처리 완료"

    return UnlinkCallbackResponse(success=True, message=message)

