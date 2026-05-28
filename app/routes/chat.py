"""
Governed multi-turn chat API.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..engines.chat_service import (
    get_session_for_user,
    list_session_messages,
    process_chat_message,
    _message_to_response,
)
from ..models import ChatMessage, ChatSession
from ..schemas import (
    ChatMessageResponse,
    ChatSendMessageRequest,
    ChatSendMessageResponse,
    ChatSessionCreate,
    ChatSessionResponse,
    ChatSessionUpdate,
)
from ..security import require_authenticated_user

router = APIRouter()


async def _session_response(db: AsyncSession, session: ChatSession) -> ChatSessionResponse:
    count = (
        await db.execute(
            select(func.count(ChatMessage.id)).where(ChatMessage.session_id == session.id)
        )
    ).scalar_one() or 0
    return ChatSessionResponse(
        id=session.id,
        title=session.title,
        region=session.region,
        guardrail_mode=session.guardrail_mode,
        output_guardrail_mode=session.output_guardrail_mode,
        inference_provider=session.inference_provider,
        model=session.model,
        created_at=session.created_at,
        updated_at=session.updated_at,
        message_count=count,
    )


@router.post("/chat/sessions", response_model=ChatSessionResponse)
async def create_session(
    body: ChatSessionCreate,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    session = ChatSession(
        user_id=user["username"],
        title=body.title or "New chat",
        region=body.region,
        guardrail_mode=body.guardrail_mode,
        output_guardrail_mode=body.output_guardrail_mode,
        inference_provider=body.inference_provider,
        model=body.model,
    )
    db.add(session)
    await db.flush()
    return await _session_response(db, session)


@router.get("/chat/sessions", response_model=List[ChatSessionResponse])
async def list_sessions(
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(ChatSession)
            .where(ChatSession.user_id == user["username"])
            .order_by(ChatSession.updated_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [await _session_response(db, s) for s in rows]


@router.get("/chat/sessions/{session_id}", response_model=ChatSessionResponse)
async def get_session(
    session_id: int,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session = await get_session_for_user(db, session_id, user["username"])
    except PermissionError:
        raise HTTPException(status_code=404, detail="Session not found")
    return await _session_response(db, session)


@router.patch("/chat/sessions/{session_id}", response_model=ChatSessionResponse)
async def update_session(
    session_id: int,
    body: ChatSessionUpdate,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session = await get_session_for_user(db, session_id, user["username"])
    except PermissionError:
        raise HTTPException(status_code=404, detail="Session not found")
    session.region = body.region
    session.guardrail_mode = body.guardrail_mode
    session.output_guardrail_mode = body.output_guardrail_mode
    session.inference_provider = body.inference_provider
    session.model = body.model
    if body.title is not None:
        session.title = body.title
    return await _session_response(db, session)


@router.delete("/chat/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: int,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session = await get_session_for_user(db, session_id, user["username"])
    except PermissionError:
        raise HTTPException(status_code=404, detail="Session not found")
    await db.delete(session)
    return Response(status_code=204)


@router.get("/chat/sessions/{session_id}/messages", response_model=List[ChatMessageResponse])
async def get_messages(
    session_id: int,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await get_session_for_user(db, session_id, user["username"])
    except PermissionError:
        raise HTTPException(status_code=404, detail="Session not found")
    messages = await list_session_messages(db, session_id)
    return [_message_to_response(m) for m in messages]


@router.post("/chat/sessions/{session_id}/messages", response_model=ChatSendMessageResponse)
async def send_message(
    session_id: int,
    body: ChatSendMessageRequest,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session = await get_session_for_user(db, session_id, user["username"])
    except PermissionError:
        raise HTTPException(status_code=404, detail="Session not found")
    return await process_chat_message(db, session, body.content, user["username"])
