from enum import Enum
from datetime import datetime
from pydantic import BaseModel

class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"

class ChatMessage(BaseModel):
    """A single chat turn stored in memory."""
    role: Role
    content: str
    include_in_history: bool = True
    timestamp: datetime = datetime.utcnow()