# beacon/auth/auth_handler.py
import os
import json
import jwt
import aiohttp
from functools import wraps
from aiohttp import web
from beacon.logs.logs import LOG
from beacon.response.catalog import build_beacon_error_response
from bson import json_util
from .lsaai import LSAAI_CONFIG, GA4GH_VISA_MAPPING

# JWKS client for token validation
from jwt.jwk import PyJWK
jwks_client = None

# Public endpoints that don't require authentication
PUBLIC_ENDPOINTS = [
    '/api/service-info',
    '/api/info',
    '/api/entry_types',
    '/api/configuration',
    '/api/map'
]

async def init_jwks_client():
    """Initialize JWKS client asynchronously"""
    global jwks_client
    if jwks_client is None:
        try:
            async with aiohttp.ClientSession() as session:
                LOG.info(f"Initializing JWKS client from {LSAAI_CONFIG['jwks_uri']}")
                async with session.get(LSAAI_CONFIG["jwks_uri"]) as resp:
                    if resp.status != 200:
                        LOG.error(f"Failed to get JWKS: {resp.status}")
                        return False
                    jwks_data = await resp.json()
                    jwks_client = {key["kid"]: PyJWK.from_dict(key) for key in jwks_data["keys"]}
                    LOG.info(f"JWKS client initialized with {len(jwks_client)} keys")
                    return True
        except Exception as e:
            LOG.error(f"Failed to initialize JWKS client: {str(e)}")
            raise
    return True

def get_public_key(kid):
    """Get public key for token verification"""
    if jwks_client is None:
        LOG.warning("JWKS client not initialized")
        return None
    return jwks_client.get(kid)

def verify_token(token):
    """Verify JWT token and return payload if valid"""
    try:
        # Extract kid from token header
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        
        if not kid:
            LOG.warning("No kid in token header")
            return None
        
        # Get public key for verification
        key = get_public_key(kid)
        if not key:
            LOG.warning(f"No public key found for kid: {kid}")
            return None
            
        # Verify token
        payload = jwt.decode(
            token,
            key.key,
            algorithms=['RS256'],
            audience=LSAAI_CONFIG["client_id"],
            issuer=LSAAI_CONFIG["issuer"]
        )
        
        return payload
    except jwt.ExpiredSignatureError:
        LOG.error("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        LOG.error(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        LOG.error(f"Token verification error: {str(e)}")
        return None

def extract_ga4gh_visas(token_payload):
    """Extract GA4GH Passport Visas from token payload"""
    visas = {}
    
    # Extract from ga4gh_passport_v1 claim if present
    if "ga4gh_passport_v1" in token_payload:
        passport_visas = token_payload["ga4gh_passport_v1"]
        if isinstance(passport_visas, list):
            for visa_jwt in passport_visas:
                try:
                    # Visas are JWTs themselves
                    visa_payload = jwt.decode(visa_jwt, options={"verify_signature": False})
                    if "ga4gh_visa_v1" in visa_payload:
                        visa_info = visa_payload["ga4gh_visa_v1"]
                        visa_type = visa_info.get("type")
                        visa_value = visa_info.get("value")
                        
                        if visa_type not in visas:
                            visas[visa_type] = []
                        
                        visas[visa_type].append(visa_value)
                except Exception as e:
                    LOG.error(f"Error decoding visa: {str(e)}")
    
    return visas

def get_authorized_datasets_from_visas(visas):
    """Determine which datasets a user is authorized to access based on visas"""
    authorized_datasets = set()
    
    # Process each visa type in the visa mapping
    for visa_type, dataset_mapping in GA4GH_VISA_MAPPING.items():
        # Check if this visa type exists in the user's visas
        if visa_type in visas:
            visa_values = visas[visa_type]
            
            # For each visa value, check if it maps to a dataset
            for visa_value in visa_values:
                if visa_value in dataset_mapping:
                    authorized_datasets.add(dataset_mapping[visa_value])
    
    return list(authorized_datasets)

# Role to permission mapping
ROLE_PERMISSION_MAP = {
    "beacon_admin": ["read_all", "write_all"],
    "beacon_researcher": ["read_public", "read_registered", "read_controlled"],
    "beacon_user": ["read_public", "read_registered"],
    "beacon_guest": ["read_public"]
}

def get_permissions_from_roles(roles):
    """Map LSAAI roles to Beacon permissions"""
    permissions = set()
    
    # If user has no roles, give public access by default
    if not roles:
        permissions.add("read_public")
        return list(permissions)
    
    for role in roles:
        if role in ROLE_PERMISSION_MAP:
            permissions.update(ROLE_PERMISSION_MAP[role])
    
    return list(permissions)

@web.middleware
async def lsaai_auth_middleware(request, handler):
    """Middleware to authenticate requests using LSAAI JWT tokens"""
    # Initialize JWKS client if not already done
    if jwks_client is None:
        success = await init_jwks_client()
        if not success:
            LOG.error("Failed to initialize JWKS client")
            
    # Skip authentication for certain public endpoints
    if any(request.path.startswith(endpoint) for endpoint in PUBLIC_ENDPOINTS):
        return await handler(request)
    
    # Extract the authorization header
    auth_header = request.headers.get('Authorization')
    
    # If no Authorization header, proceed as unauthenticated (public access only)
    if not auth_header or not auth_header.startswith('Bearer '):
        LOG.info("No Authorization header, proceeding with public access only")
        request['lsaai_token_info'] = {}
        request['lsaai_permissions'] = ["read_public"]
        request['lsaai_visa_datasets'] = []
        return await handler(request)
    
    # Extract the token
    token = auth_header.split(' ')[1]
    
    # Verify token
    token_payload = verify_token(token)
    
    if not token_payload:
        LOG.warning("Invalid token")
        response_obj = build_beacon_error_response(None, 401, 'Unauthorized', 'Invalid authorization token')
        return web.Response(text=json_util.dumps(response_obj), status=401, content_type='application/json')
    
    # Extract user info
    user_id = token_payload.get('sub', 'anonymous')
    LOG.info(f"Authenticated user: {user_id}")
    
    # Extract roles from token_payload
    roles = token_payload.get('roles', [])
    if isinstance(roles, str):
        # Handle case where roles might be a comma-separated string
        roles = [role.strip() for role in roles.split(',')]
    
    # Extract GA4GH visas
    ga4gh_visas = extract_ga4gh_visas(token_payload)
    
    # Map roles to permissions
    permissions = get_permissions_from_roles(roles)
    
    # Get authorized datasets from visas
    visa_datasets = get_authorized_datasets_from_visas(ga4gh_visas)
    
    # Store token info, permissions and visa datasets in request
    request['lsaai_token_info'] = token_payload
    request['lsaai_permissions'] = permissions
    request['lsaai_visa_datasets'] = visa_datasets
    
    # Log authenticated request
    LOG.info(f"User {user_id} has permissions: {permissions}")
    if visa_datasets:
        LOG.info(f"User {user_id} has visa access to datasets: {visa_datasets}")
    
    # Continue with the request
    return await handler(request)

def lsaai_dataset_permissions(func):
    """Decorator to check dataset permissions using LSAAI roles and visas"""
    @wraps(func)
    async def wrapper(self, post_data, request, qparams, entry_type, entry_id, headers=None):
        # Get the token info, permissions and visa datasets from the request
        token_info = request.get('lsaai_token_info', {})
        permissions = request.get('lsaai_permissions', [])
        visa_datasets = request.get('lsaai_visa_datasets', [])
        
        user_id = token_info.get('sub', 'anonymous')
        
        # Log the inputs for debugging
        LOG.info(f"LSAAI permissions check: user={user_id}, permissions={permissions}, entry_type={entry_type}")
        
        # Determine accessible datasets based on permissions
        if 'read_all' in permissions:
            # Admin can access all datasets
            LOG.info(f"User {user_id} has full admin access")
            # Pass None to indicate full access
            return await func(self, post_data, request, qparams, entry_type, entry_id, None, headers)
        
        # For non-admin users, filter datasets based on permissions and visas
        if len(permissions) > 0 or len(visa_datasets) > 0:
            LOG.info(f"User {user_id} has limited access with permissions {permissions}")
            
            # Import here to avoid circular imports
            from beacon.db.datasets import get_datasets
            
            all_datasets = await get_datasets()
            
            authorized_datasets = []
            for dataset in all_datasets:
                dataset_id = dataset.get('id')
                
                # First check for visa-based access
                if dataset_id in visa_datasets:
                    LOG.info(f"User has visa-based access to dataset {dataset_id}")
                    authorized_datasets.append(dataset)
                    continue
                
                # Then check for permission-based access based on security level
                # Use accessLevel or securityLevel based on your dataset structure
                access_level = (
                    dataset.get('accessLevel') or 
                    dataset.get('access_level') or 
                    dataset.get('securityLevel', 'CONTROLLED')
                ).upper()
                
                # Map security level to required permission
                if access_level == 'PUBLIC' and 'read_public' in permissions:
                    authorized_datasets.append(dataset)
                elif access_level == 'REGISTERED' and 'read_registered' in permissions:
                    authorized_datasets.append(dataset)
                elif access_level == 'CONTROLLED' and 'read_controlled' in permissions:
                    authorized_datasets.append(dataset)
            
            # Log the authorized datasets
            dataset_ids = [d.get('id') for d in authorized_datasets]
            LOG.info(f"User {user_id} authorized datasets: {dataset_ids}")
            
            # Call the original function with filtered datasets
            return await func(self, post_data, request, qparams, entry_type, entry_id, authorized_datasets, headers)
        else:
            # No permissions - provide empty dataset list (public access)
            LOG.warning(f"User {user_id} has insufficient permissions - providing empty dataset list")
            return await func(self, post_data, request, qparams, entry_type, entry_id, [], headers)
    
    return wrapper