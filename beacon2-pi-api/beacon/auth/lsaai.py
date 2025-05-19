"""
LSAAI Authentication configuration
"""

LSAAI_CONFIG = {
    "issuer": "http://aai-mock:8080/oidc/",
    "jwks_uri": "http://aai-mock:8080/oidc/jwk",
    "userinfo_endpoint": "http://aai-mock:8080/oidc/userinfo",
    "introspection_endpoint": "http://aai-mock:8080/oidc/introspect",
    "client_id": "beacon-api",
    "client_secret": "beacon-secret"
}

# Map GA4GH visa types to permissions
GA4GH_VISA_MAPPING = {
    "ControlledAccessGrants": {
        # Map visa values to dataset IDs
        "urn:beacon:CINECA_synthetic_cohort_EUROPE_UK1": "CINECA_synthetic_cohort_EUROPE_UK1",
        "urn:beacon:dataset2": "dataset2",
        # Add more mappings as needed
    }
}