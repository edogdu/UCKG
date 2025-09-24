from collections import deque
from typing import Deque, Dict
from .chat_types import ChatMessage, Role

class ChatMemory:
    """Ring buffer chat history for a single session."""
    def __init__(self, max_len: int = 50):
        self._buf: Deque[ChatMessage] = deque(maxlen=max_len)
        # add initial system message
        self._buf.append(ChatMessage(role=Role.SYSTEM, content="You are a helpful cybersecurity assistant."))

    def add(self, msg: ChatMessage):
        self._buf.append(msg)

    def formatted_history(self) -> str:
        lines = []
        for m in self._buf:
            if m.include_in_history:
                lines.append(f"{m.role.value.upper()}: {m.content}")
        return "\n".join(lines)

_sessions: Dict[str, ChatMemory] = {}

def get_memory(session_id: str) -> ChatMemory:
    if session_id not in _sessions:
        _sessions[session_id] = ChatMemory()
    return _sessions[session_id]