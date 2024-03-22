from typing import Optional
from pydantic import BaseModel

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str
    
class CommentCreate(BaseModel):
    text: str

class UserInToken(BaseModel):
    id: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
