
import secrets
import string
from typing import Dict, Any

def generate_scripthub_token(length: int = 64) -> str:
    """Generate a secure random token for scripthub identification"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def create_default_customer_data() -> Dict[str, Any]:
    """Create default data structure for new customers"""
    return {
        "max_scripthubs": 1,
        "max_keys": 200
    }

def create_scripthub_structure(name: str, max_keys: int = 200, key_timelimit: int = 16, checkpoints: int = 1) -> Dict[str, Any]:
    """Create a new scripthub structure"""
    return {
        name: {
            "token": generate_scripthub_token(),
            "max_keys": max_keys,
            "key_timelimit": key_timelimit,
            "maxCheckpoints": 10,
            "checkpoints": checkpoints,
            "cryptixCheckpoint": 1,
            "checkpointData": {
                "linkvertise": None,
                "lootlabs": None
            },
            "keys": {}
        }
    }

def validate_scripthub_limits(customer_data: Dict[str, Any], scripthub_name: str) -> tuple[bool, str]:
    """Validate if customer can create a new scripthub"""
    # Count existing scripthubs (exclude max_scripthubs and max_keys)
    existing_scripthubs = sum(1 for key in customer_data.keys() 
                            if key not in ["max_scripthubs", "max_keys"])
    
    max_allowed = customer_data.get("max_scripthubs", 1)
    
    # Check if limit exceeded
    if existing_scripthubs >= max_allowed:
        return False, f"Maximum scripthub limit reached ({max_allowed})"
    
    # Check if scripthub name already exists
    if scripthub_name in customer_data:
        return False, "Scripthub with this name already exists"
    
    return True, "Valid"
