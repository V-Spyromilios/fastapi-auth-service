from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserPublic(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime
