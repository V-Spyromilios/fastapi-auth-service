from fastapi import APIRouter, Depends

from app.api.deps import get_current_user_dep
from app.schemas.users import UserPublic

router = APIRouter()


@router.get("/me", response_model=UserPublic)
def get_me(current_user: UserPublic = Depends(get_current_user_dep)) -> UserPublic:
    return current_user
