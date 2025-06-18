
from fastapi import APIRouter, HTTPException, Depends, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.database import get_customer_data, update_customer_data
from utils.scripthub import (
    create_default_customer_data, 
    create_scripthub_structure, 
    validate_scripthub_limits
)
from models.user import ScripthubCreate, ScripthubResponse
from routes.auth import authenticate_token

# Initialize router
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

@router.post("/create/scripthub", response_model=ScripthubResponse)
@limiter.limit("10/5minutes")
async def create_scripthub(
    request: Request, 
    scripthub_data: ScripthubCreate,
    user = Depends(authenticate_token)
):
    try:
        user_id = str(user["_id"])
        
        # Get existing customer data or create default
        customer_data = await get_customer_data(user_id)
        if not customer_data:
            customer_data = create_default_customer_data()
        
        # Validate scripthub limits and name
        is_valid, error_message = validate_scripthub_limits(customer_data, scripthub_data.name)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )
        
        # Create new scripthub structure
        max_keys = customer_data.get("max_keys", 200)
        new_scripthub = create_scripthub_structure(scripthub_data.name, max_keys)
        
        # Update customer data with new scripthub
        customer_data.update(new_scripthub)
        
        # Save to database
        update_success = await update_customer_data(user_id, customer_data)
        if not update_success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create scripthub"
            )
        
        return ScripthubResponse(
            success=True,
            message="Scripthub created successfully",
            scripthub={
                "name": scripthub_data.name,
                "token": new_scripthub[scripthub_data.name]["token"],
                "max_keys": new_scripthub[scripthub_data.name]["max_keys"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as error:
        print(f"Scripthub creation error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scripthub"
        )

@router.get("/scripthubs")
@limiter.limit("20/5minutes")
async def get_scripthubs(request: Request, user = Depends(authenticate_token)):
    """Get all scripthubs for authenticated user"""
    try:
        user_id = str(user["_id"])
        customer_data = await get_customer_data(user_id)
        
        if not customer_data:
            return {
                "success": True,
                "scripthubs": [],
                "limits": {
                    "max_scripthubs": 1,
                    "max_keys": 200
                }
            }
        
        # Extract scripthubs (exclude system fields)
        scripthubs = []
        for key, value in customer_data.items():
            if key not in ["max_scripthubs", "max_keys"]:
                scripthubs.append({
                    "name": key,
                    "token": value["token"],
                    "max_keys": value["max_keys"],
                    "current_keys": len(value["keys"])
                })
        
        return {
            "success": True,
            "scripthubs": scripthubs,
            "limits": {
                "max_scripthubs": customer_data.get("max_scripthubs", 1),
                "max_keys": customer_data.get("max_keys", 200)
            }
        }
        
    except Exception as error:
        print(f"Get scripthubs error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scripthubs"
        )
