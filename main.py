
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from utils.database import connect_db
from routes.auth import router as auth_router
from routes.scripthub import router as scripthub_router
import os

app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware (add before SlowAPI middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add SlowAPI middleware after CORS
app.add_middleware(SlowAPIMiddleware)

# Include routers
app.include_router(auth_router, prefix="/api/v1/users")
app.include_router(scripthub_router, prefix="/api/v1")

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

@app.get("/")
async def read_root():
    return {"message": "Welcome to the Cryptix API"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))  # Changed default port to 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
