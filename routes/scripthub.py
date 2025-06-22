from fastapi import APIRouter, HTTPException, Depends, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.database import get_customer_data, update_customer_data
from utils.scripthub import (
    create_default_customer_data, 
    create_scripthub_structure, 
    validate_scripthub_limits
)
from models.user import ScripthubCreate, ScripthubResponse, ScripthubListResponse, ScripthubInfo, ScripthubLimits, ScripthubUpdate
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
        new_scripthub = create_scripthub_structure(scripthub_data.name, max_keys, scripthub_data.key_timelimit)

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
                "max_keys": new_scripthub[scripthub_data.name]["max_keys"],
                "key_timelimit": new_scripthub[scripthub_data.name]["key_timelimit"],
                "maxCheckpoints": new_scripthub[scripthub_data.name]["maxCheckpoints"],
                "checkpoints": new_scripthub[scripthub_data.name]["checkpoints"],
                "cryptixCheckpoint": new_scripthub[scripthub_data.name]["cryptixCheckpoint"],
                "checkpointData": new_scripthub[scripthub_data.name]["checkpointData"]
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

@router.get("/scripthubs", response_model=ScripthubListResponse)
@limiter.limit("20/5minutes")
async def get_scripthubs(request: Request, user = Depends(authenticate_token)):
    """Get all scripthubs for authenticated user"""
    try:
        user_id = str(user["_id"])
        customer_data = await get_customer_data(user_id)

        if not customer_data:
            return ScripthubListResponse(
                success=True,
                scripthubs=[],
                limits=ScripthubLimits(max_scripthubs=1, max_keys=200)
            )

        # Extract scripthubs (exclude system fields)
        scripthubs = []
        for key, value in customer_data.items():
            if key not in ["max_scripthubs", "max_keys"]:
                scripthubs.append(ScripthubInfo(
                    name=key,
                    token=value["token"],
                    max_keys=value["max_keys"],
                    current_keys=len(value["keys"]),
                    key_timelimit=value.get("key_timelimit", 16),
                    maxCheckpoints=value.get("maxCheckpoints", 10),
                    checkpoints=value.get("checkpoints", 1),
                    cryptixCheckpoint=value.get("cryptixCheckpoint", 1),
                    checkpointData=value.get("checkpointData", {
                        "linkvertise": None,
                        "rinku": None,
                        "lootlabs": None
                    })
                ))

        return ScripthubListResponse(
            success=True,
            scripthubs=scripthubs,
            limits=ScripthubLimits(
                max_scripthubs=customer_data.get("max_scripthubs", 1),
                max_keys=customer_data.get("max_keys", 200)
            )
        )

    except Exception as error:
        print(f"Get scripthubs error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scripthubs"
        )

@router.delete("/scripthub/{scripthub_name}")
@limiter.limit("10/5minutes")
async def delete_scripthub(
    request: Request, 
    scripthub_name: str,
    user = Depends(authenticate_token)
):
    """Delete a scripthub"""
    try:
        user_id = str(user["_id"])
        customer_data = await get_customer_data(user_id)

        # Check if scripthub exists (exclude system fields)
        if not customer_data or scripthub_name not in customer_data or scripthub_name in ["max_scripthubs", "max_keys"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scripthub '{scripthub_name}' not found"
            )

        # Remove the scripthub
        del customer_data[scripthub_name]

        # Save to database
        update_success = await update_customer_data(user_id, customer_data)
        if not update_success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete scripthub"
            )

        return {"success": True, "message": "Scripthub deleted successfully"}

    except HTTPException:
        raise
    except Exception as error:
        print(f"Delete scripthub error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scripthub"
        )

@router.put("/scripthub/{scripthub_name}")
@limiter.limit("10/5minutes")
async def update_scripthub(
    request: Request, 
    scripthub_name: str,
    update_data: ScripthubUpdate,
    user = Depends(authenticate_token)
):
    """Update scripthub name and time limit"""
    try:
        user_id = str(user["_id"])
        customer_data = await get_customer_data(user_id)

        # Check if scripthub exists (exclude system fields)
        if not customer_data or scripthub_name not in customer_data or scripthub_name in ["max_scripthubs", "max_keys"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scripthub '{scripthub_name}' not found"
            )

        # Check if new name already exists (only if it's different from current name)
        if update_data.new_name != scripthub_name and update_data.new_name in customer_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scripthub with new name already exists"
            )

        # Get existing scripthub data
        scripthub_data = customer_data[scripthub_name]

        # Update only provided fields
        if update_data.key_timelimit is not None:
            scripthub_data["key_timelimit"] = update_data.key_timelimit
        if update_data.maxCheckpoints is not None:
            scripthub_data["maxCheckpoints"] = update_data.maxCheckpoints
        if update_data.checkpoints is not None:
            scripthub_data["checkpoints"] = update_data.checkpoints
        if update_data.cryptixCheckpoint is not None:
            scripthub_data["cryptixCheckpoint"] = update_data.cryptixCheckpoint
        if update_data.checkpointData is not None:
            scripthub_data["checkpointData"] = update_data.checkpointData

        # If name is changing, create new entry and delete old one
        if update_data.new_name is not None and update_data.new_name != scripthub_name:
            customer_data[update_data.new_name] = scripthub_data
            del customer_data[scripthub_name]
            scripthub_name = update_data.new_name

        # Save to database
        update_success = await update_customer_data(user_id, customer_data)
        if not update_success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update scripthub"
            )

        return {
            "success": True, 
            "message": "Scripthub updated successfully",
            "scripthub": {
                "name": scripthub_name,
                "token": scripthub_data["token"],
                "max_keys": scripthub_data["max_keys"],
                "key_timelimit": scripthub_data["key_timelimit"],
                "maxCheckpoints": scripthub_data.get("maxCheckpoints", 10),
                "checkpoints": scripthub_data.get("checkpoints", 1),
                "cryptixCheckpoint": scripthub_data.get("cryptixCheckpoint", 1),
                "checkpointData": scripthub_data.get("checkpointData", {
                    "linkvertise": None,
                    "rinku": None,
                    "lootlabs": None
                })
            }
        }

    except HTTPException:
        raise
    except Exception as error:
        print(f"Update scripthub error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update scripthub"
        )