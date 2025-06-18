
import os
import bcrypt
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# MongoDB connection
client = None
db = None

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
    try:
        return await db.customers.find_one({"_id": ObjectId(user_id)})
    except:
        return None

async def create_user(username: str, password: str):
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
