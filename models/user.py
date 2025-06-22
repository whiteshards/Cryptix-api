
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

class ScripthubCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    checkpoints: int = Field(..., ge=1)  # Mandatory checkpoints field
    
    class Config:
        str_strip_whitespace = True

class ScripthubUpdate(BaseModel):
    new_name: str = Field(None, min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    key_timelimit: int = Field(None, ge=1, le=8760)  # 1 hour to 1 year
    checkpoints: int = Field(None, ge=1)  # Only checkpoints can be updated
    
    class Config:
        str_strip_whitespace = True

class ScripthubResponse(BaseModel):
    success: bool
    message: str
    scripthub: dict

class ScripthubInfo(BaseModel):
    name: str
    token: str
    max_keys: int
    current_keys: int
    key_timelimit: int
    maxCheckpoints: int
    checkpoints: int
    cryptixCheckpoint: int
    checkpointData: dict

class ScripthubLimits(BaseModel):
    max_scripthubs: int
    max_keys: int

class ScripthubListResponse(BaseModel):
    success: bool
    scripthubs: list[ScripthubInfo]
    limits: ScripthubLimits
