import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
import logging
from enum import Enum
import hashlib

class AccessLevel(Enum):
    """Access level enumeration"""
    READ = 1
    WRITE = 2
    ADMIN = 3

class AccessControlSystem:
    def __init__(self, storage_path: str = "access_control.json"):
        """Initialize Access Control System"""
        self.storage_path = storage_path
        self.policies = self._load_policies()
        
        # Setup logging
        logging.basicConfig(
            filename='access_control.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _load_policies(self) -> Dict:
        """Load access control policies from storage"""
        try:
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'roles': {},
                'users': {},
                'resources': {},
                'attributes': {},
                'time_policies': {}
            }

    def _save_policies(self):
        """Save access control policies to storage"""
        with open(self.storage_path, 'w') as f:
            json.dump(self.policies, f, indent=4)

    def add_role(self, role_name: str, permissions: List[str]):
        """Add or update a role with specified permissions"""
        self.policies['roles'][role_name] = {
            'permissions': permissions,
            'created_at': datetime.now().isoformat()
        }
        self._save_policies()
        logging.info(f"Added/updated role: {role_name}")

    def assign_role(self, user_id: str, role_name: str):
        """Assign a role to a user"""
        if role_name not in self.policies['roles']:
            raise ValueError(f"Role {role_name} does not exist")
            
        if user_id not in self.policies['users']:
            self.policies['users'][user_id] = {'roles': []}
            
        if role_name not in self.policies['users'][user_id]['roles']:
            self.policies['users'][user_id]['roles'].append(role_name)
            self._save_policies()
            logging.info(f"Assigned role {role_name} to user {user_id}")

    def check_permission(self, user_id: str, permission: str) -> bool:
        """Check if a user has a specific permission"""
        if user_id not in self.policies['users']:
            return False
            
        user_roles = self.policies['users'][user_id]['roles']
        for role in user_roles:
            if role in self.policies['roles'] and \
               permission in self.policies['roles'][role]['permissions']:
                return True
        return False

    def add_attribute_policy(self, name: str, conditions: Dict[str, Any]):
        """Add an attribute-based access control policy"""
        self.policies['attributes'][name] = {
            'conditions': conditions,
            'created_at': datetime.now().isoformat()
        }
        self._save_policies()
        logging.info(f"Added attribute policy: {name}")

    def check_attribute_access(self, user_attributes: Dict[str, Any],
                             resource_attributes: Dict[str, Any],
                             policy_name: str) -> bool:
        """Check access based on attributes"""
        if policy_name not in self.policies['attributes']:
            return False
            
        policy = self.policies['attributes'][policy_name]
        conditions = policy['conditions']
        
        # Example attribute checking logic
        for key, value in conditions.items():
            if key.startswith('user.'):
                attr = key[5:]  # Remove 'user.' prefix
                if attr not in user_attributes or user_attributes[attr] != value:
                    return False
            elif key.startswith('resource.'):
                attr = key[9:]  # Remove 'resource.' prefix
                if attr not in resource_attributes or \
                   resource_attributes[attr] != value:
                    return False
                    
        return True

    def add_time_based_policy(self, policy_name: str, start_time: str,
                             end_time: str, allowed_days: Set[int] = None):
        """Add a time-based access control policy"""
        if allowed_days is None:
            allowed_days = set(range(7))  # All days
            
        self.policies['time_policies'][policy_name] = {
            'start_time': start_time,
            'end_time': end_time,
            'allowed_days': list(allowed_days),
            'created_at': datetime.now().isoformat()
        }
        self._save_policies()
        logging.info(f"Added time-based policy: {policy_name}")

    def check_time_based_access(self, policy_name: str,
                              check_time: datetime = None) -> bool:
        """Check access based on time policies"""
        if policy_name not in self.policies['time_policies']:
            return False
            
        if check_time is None:
            check_time = datetime.now()
            
        policy = self.policies['time_policies'][policy_name]
        
        # Check if current day is allowed
        if check_time.weekday() not in policy['allowed_days']:
            return False
            
        # Parse time strings
        start_time = datetime.strptime(policy['start_time'], '%H:%M').time()
        end_time = datetime.strptime(policy['end_time'], '%H:%M').time()
        current_time = check_time.time()
        
        return start_time <= current_time <= end_time

    def create_resource(self, resource_id: str, attributes: Dict[str, Any] = None):
        """Create a new resource with attributes"""
        if attributes is None:
            attributes = {}
            
        self.policies['resources'][resource_id] = {
            'attributes': attributes,
            'created_at': datetime.now().isoformat()
        }
        self._save_policies()
        logging.info(f"Created resource: {resource_id}")

    def check_access(self, user_id: str, resource_id: str,
                    action: str) -> Tuple[bool, str]:
        """Comprehensive access check combining multiple policies"""
        # Check if user and resource exist
        if user_id not in self.policies['users']:
            return False, "User not found"
        if resource_id not in self.policies['resources']:
            return False, "Resource not found"
            
        # Check role-based permissions
        if not self.check_permission(user_id, f"{action}:{resource_id}"):
            return False, "Insufficient permissions"
            
        # Get user and resource attributes
        user_attrs = self.policies['users'][user_id].get('attributes', {})
        resource_attrs = self.policies['resources'][resource_id]['attributes']
        
        # Check attribute policies
        for policy_name in self.policies['attributes']:
            if not self.check_attribute_access(user_attrs, resource_attrs,
                                            policy_name):
                return False, f"Failed attribute policy: {policy_name}"
                
        # Check time-based policies
        for policy_name in self.policies['time_policies']:
            if not self.check_time_based_access(policy_name):
                return False, f"Failed time-based policy: {policy_name}"
                
        return True, "Access granted"

    def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for a user"""
        permissions = set()
        if user_id in self.policies['users']:
            for role in self.policies['users'][user_id]['roles']:
                if role in self.policies['roles']:
                    permissions.update(self.policies['roles'][role]['permissions'])
        return permissions

    def revoke_access(self, user_id: str, role_name: str = None):
        """Revoke user access (either specific role or all roles)"""
        if user_id not in self.policies['users']:
            return
            
        if role_name:
            if role_name in self.policies['users'][user_id]['roles']:
                self.policies['users'][user_id]['roles'].remove(role_name)
                logging.info(f"Revoked role {role_name} from user {user_id}")
        else:
            self.policies['users'][user_id]['roles'] = []
            logging.info(f"Revoked all roles from user {user_id}")
            
        self._save_policies()

# Example usage
if __name__ == "__main__":
    # Initialize Access Control System
    acs = AccessControlSystem()
    
    # Example 1: Create roles and permissions
    acs.add_role('admin', ['read:*', 'write:*', 'delete:*'])
    acs.add_role('user', ['read:public_docs', 'write:own_docs'])
    
    # Example 2: Assign roles to users
    acs.assign_role('user123', 'user')
    acs.assign_role('admin456', 'admin')
    
    # Example 3: Create a resource
    acs.create_resource('doc123', {
        'owner': 'user123',
        'classification': 'public'
    })
    
    # Example 4: Add attribute-based policy
    acs.add_attribute_policy('document_access', {
        'user.clearance_level': 'secret',
        'resource.classification': 'secret'
    })
    
    # Example 5: Add time-based policy
    acs.add_time_based_policy('business_hours', '09:00', '17:00', {0,1,2,3,4})
    
    # Example 6: Check access
    access_granted, reason = acs.check_access('user123', 'doc123', 'read')
    print(f"Access check result: {access_granted}, Reason: {reason}")
    
    # Example 7: Get user permissions
    permissions = acs.get_user_permissions('admin456')
    print(f"Admin permissions: {permissions}")
    
    # Example 8: Revoke access
    acs.revoke_access('user123', 'user')
    print("Revoked user role from user123")