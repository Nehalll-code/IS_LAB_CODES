import json
import time
import os
import hashlib
import base64
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import logging

class KeyManagementSystem:
    def __init__(self, storage_path: str = "keystore.json"):
        """Initialize Key Management System"""
        self.storage_path = storage_path
        self.keys = self._load_keys()
        
        # Setup logging
        logging.basicConfig(
            filename='key_management.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _load_keys(self) -> Dict:
        """Load keys from storage"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_keys(self):
        """Save keys to storage"""
        with open(self.storage_path, 'w') as f:
            json.dump(self.keys, f, indent=4)

    def generate_key_id(self, entity_id: str, key_type: str) -> str:
        """Generate unique key ID"""
        timestamp = str(int(time.time()))
        data = f"{entity_id}:{key_type}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def add_key(self, entity_id: str, key_type: str, key_data: Dict,
                expiry_days: int = 365) -> str:
        """Add a new key to the system"""
        key_id = self.generate_key_id(entity_id, key_type)
        
        # Calculate expiry date
        creation_time = datetime.now()
        expiry_time = creation_time + timedelta(days=expiry_days)
        
        key_entry = {
            'entity_id': entity_id,
            'key_type': key_type,
            'key_data': key_data,
            'creation_time': creation_time.isoformat(),
            'expiry_time': expiry_time.isoformat(),
            'status': 'active'
        }
        
        self.keys[key_id] = key_entry
        self._save_keys()
        
        logging.info(f"Added new key {key_id} for entity {entity_id}")
        return key_id

    def get_key(self, key_id: str) -> Optional[Dict]:
        """Retrieve a key by its ID"""
        if key_id in self.keys:
            key = self.keys[key_id]
            if key['status'] == 'active' and \
               datetime.fromisoformat(key['expiry_time']) > datetime.now():
                return key
            else:
                logging.warning(f"Attempted to access expired/revoked key {key_id}")
                return None
        return None

    def revoke_key(self, key_id: str, reason: str = "Not specified"):
        """Revoke a key"""
        if key_id in self.keys:
            self.keys[key_id]['status'] = 'revoked'
            self.keys[key_id]['revocation_reason'] = reason
            self.keys[key_id]['revocation_time'] = datetime.now().isoformat()
            self._save_keys()
            
            logging.info(f"Revoked key {key_id}. Reason: {reason}")
            return True
        return False

    def rotate_key(self, key_id: str, new_key_data: Dict) -> Optional[str]:
        """Rotate a key with new key data"""
        if key_id in self.keys:
            old_key = self.keys[key_id]
            
            # Create new key with same parameters
            new_key_id = self.add_key(
                old_key['entity_id'],
                old_key['key_type'],
                new_key_data
            )
            
            # Revoke old key
            self.revoke_key(key_id, reason="Key rotation")
            
            logging.info(f"Rotated key {key_id} to new key {new_key_id}")
            return new_key_id
        return None

    def list_keys(self, entity_id: Optional[str] = None,
                  key_type: Optional[str] = None,
                  include_expired: bool = False) -> List[Dict]:
        """List keys with optional filters"""
        results = []
        current_time = datetime.now()
        
        for key_id, key in self.keys.items():
            if entity_id and key['entity_id'] != entity_id:
                continue
            if key_type and key['key_type'] != key_type:
                continue
                
            expiry_time = datetime.fromisoformat(key['expiry_time'])
            if not include_expired and expiry_time <= current_time:
                continue
                
            results.append({
                'key_id': key_id,
                **key
            })
            
        return results

    def check_expiring_keys(self, days_threshold: int = 30) -> List[str]:
        """Check for keys expiring soon"""
        threshold_date = datetime.now() + timedelta(days=days_threshold)
        expiring_keys = []
        
        for key_id, key in self.keys.items():
            if key['status'] != 'active':
                continue
                
            expiry_time = datetime.fromisoformat(key['expiry_time'])
            if expiry_time <= threshold_date:
                expiring_keys.append(key_id)
                
        return expiring_keys

    def get_key_metrics(self) -> Dict[str, Any]:
        """Get metrics about the key management system"""
        total_keys = len(self.keys)
        active_keys = len([k for k in self.keys.values() if k['status'] == 'active'])
        revoked_keys = total_keys - active_keys
        
        key_types = {}
        entities = {}
        
        for key in self.keys.values():
            key_types[key['key_type']] = key_types.get(key['key_type'], 0) + 1
            entities[key['entity_id']] = entities.get(key['entity_id'], 0) + 1
            
        return {
            'total_keys': total_keys,
            'active_keys': active_keys,
            'revoked_keys': revoked_keys,
            'key_types_distribution': key_types,
            'entities_distribution': entities
        }

# Example usage
if __name__ == "__main__":
    # Initialize KMS
    kms = KeyManagementSystem()
    
    # Example 1: Add new RSA key pair
    rsa_key_data = {
        'public_key': 'example_public_key',
        'private_key': 'example_private_key'
    }
    key_id = kms.add_key('user1', 'RSA', rsa_key_data)
    print(f"Added new RSA key: {key_id}")
    
    # Example 2: Retrieve key
    key = kms.get_key(key_id)
    print(f"Retrieved key: {key}")
    
    # Example 3: List all active keys
    active_keys = kms.list_keys()
    print(f"Active keys: {active_keys}")
    
    # Example 4: Rotate key
    new_rsa_key_data = {
        'public_key': 'new_public_key',
        'private_key': 'new_private_key'
    }
    new_key_id = kms.rotate_key(key_id, new_rsa_key_data)
    print(f"Rotated key. New key ID: {new_key_id}")
    
    # Example 5: Get system metrics
    metrics = kms.get_key_metrics()
    print(f"System metrics: {metrics}")