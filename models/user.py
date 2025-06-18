
from pydantic import BaseModel, Field
from datetime import datetime
import re

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r'^[a-zA-Z0-9_]+$')
    password: str = Field(..., min_length=8)
    
    class Config:
        str_strip_whitespace = True

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    createdAt: datetime

class TokenResponse(BaseModel):
    success: bool
    token: str
    customer: UserResponse

class ProfileResponse(BaseModel):
    success: bool
    customer: UserResponse

class ProtectedResponse(BaseModel):
    success: bool
    message: str
    customer: str
