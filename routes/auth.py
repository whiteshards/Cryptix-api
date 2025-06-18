
import os
import jwt
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.database import find_user_by_username, find_user_by_id, create_user, verify_password

# Initialize router and security
router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)

# Pydantic models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, regex=r'^[a-zA-Z0-9_]+$')
    password: str = Field(..., min_length=8)

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

# Helper functions
def generate_token(user_id: str) -> str:
    jwt_secret = os.getenv('JWT_SECRET')
    if not jwt_secret:
        raise ValueError("JWT_SECRET environment variable is required")
    
    payload = {
        "userId": user_id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, jwt_secret, algorithm="HS256")

async def authenticate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    jwt_secret = os.getenv('JWT_SECRET')
    if not jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT_SECRET not configured"
        )
    
    try:
        token = credentials.credentials
        decoded = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        user_id = decoded.get("userId")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        user = await find_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return user
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired token"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired token"
        )

def format_user_response(user) -> UserResponse:
    return UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        createdAt=user["createdAt"]
    )

# Routes
@router.post("/register", response_model=TokenResponse)
@limiter.limit("5/15minutes")
async def register(request: Request, user_data: UserCreate):
    try:
        # Check if user already exists
        existing_user = await find_user_by_username(user_data.username)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        
        # Create new user
        user = await create_user(user_data.username, user_data.password)
        token = generate_token(str(user["_id"]))
        
        return TokenResponse(
            success=True,
            token=token,
            customer=format_user_response(user)
        )
        
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/15minutes")
async def login(request: Request, user_data: UserLogin):
    try:
        # Find user
        user = await find_user_by_username(user_data.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Verify password
        if not verify_password(user_data.password, user["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Generate token
        token = generate_token(str(user["_id"]))
        
        return TokenResponse(
            success=True,
            token=token,
            customer=format_user_response(user)
        )
        
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(user = Depends(authenticate_token)):
    return ProfileResponse(
        success=True,
        customer=format_user_response(user)
    )

@router.get("/protected", response_model=ProtectedResponse)
async def protected_route(user = Depends(authenticate_token)):
    return ProtectedResponse(
        success=True,
        message="This is a protected route",
        customer=user["username"]
    )
