#!/usr/bin/env python3
"""
Generate a random token signing secret for JWT authentication.
Equivalent to the C# code:
    var randomBytes = RandomNumberGenerator.GetBytes(32);
    var base64Secret = Convert.ToBase64String(randomBytes);
"""

import secrets
import base64

def generate_token_secret():
    """Generate a 32-byte random secret and encode it as base64."""
    # Generate 32 random bytes (cryptographically secure)
    random_bytes = secrets.token_bytes(32)

    # Convert to base64 string
    base64_secret = base64.b64encode(random_bytes).decode('utf-8')

    return base64_secret

if __name__ == "__main__":
    secret = generate_token_secret()
    print(f"TokenSigningSecret: {secret}")
