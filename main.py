
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import asyncio

app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# MongoDB connection
client = None
db = None

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

# Database functions
async def connect_db():
    global client, db
    try:
        mongodb_uri = os.getenv('MONGODB_URI')
        if not mongodb_uri:
            raise ValueError("MONGODB_URI environment variable is required")
        
        client = AsyncIOMotorClient(mongodb_uri)
        db = client['Cryptix']
        
        # Create unique index on username
        await db.customers.create_index([("username", 1)], unique=True)
        
    except Exception as error:
        print(f"Database connection failed: {error}")
        raise

async def find_user_by_username(username: str):
    return await db.customers.find_one({"username": username})

async def find_user_by_id(user_id: str):
    from bson import ObjectId
    try:
        return await db.customers.find_one({"_id": ObjectId(user_id)})
    except:
        return None

async def create_user(username: str, password: str):
    from bson import ObjectId
    
    # Hash password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    user_doc = {
        "username": username,
        "password": hashed_password,
        "createdAt": datetime.utcnow()
    }
    
    result = await db.customers.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return user_doc

def verify_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

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
@app.post("/api/v1/users/register", response_model=TokenResponse)
@limiter.limit("5/15minutes")
async def register(request, user_data: UserCreate):
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

@app.post("/api/v1/users/login", response_model=TokenResponse)
@limiter.limit("5/15minutes")
async def login(request, user_data: UserLogin):
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

@app.get("/api/v1/users/profile", response_model=ProfileResponse)
async def get_profile(user = Depends(authenticate_token)):
    return ProfileResponse(
        success=True,
        customer=format_user_response(user)
    )

@app.get("/api/v1/users/protected", response_model=ProtectedResponse)
async def protected_route(user = Depends(authenticate_token)):
    return ProtectedResponse(
        success=True,
        message="This is a protected route",
        customer=user["username"]
    )

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return {"error": "Route not found"}

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return {"error": "Internal server error"}

# Startup event
@app.on_event("startup")
async def startup_event():
    await connect_db()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
