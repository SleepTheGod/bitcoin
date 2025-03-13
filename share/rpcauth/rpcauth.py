#!/usr/bin/env python3
# Copyright (c) 2015-2025 The Bitcoin Core developers
# Licensed under the MIT software license.
# Enhanced for cryptographic excellence by Taylor Christian Newsome, 2025

import argparse
import json
import hmac
import hashlib
import os
import base64
import binascii
from getpass import getpass
from secrets import token_bytes
from typing import Tuple
import logging
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Security constants
MIN_SALT_SIZE = 16  
MIN_PASSWORD_SIZE = 32  
MIN_PBKDF2_ITERATIONS = 310_000  
DEFAULT_ALGORITHM = "sha512"  
SUPPORTED_ALGORITHMS = ["sha256", "sha512", "blake2b"]
MIN_MANUAL_PASSWORD_LENGTH = 12  

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def generate_salt(size: int = MIN_SALT_SIZE) -> str:
    """Generate a cryptographically secure salt."""
    salt = token_bytes(size)
    return binascii.hexlify(salt).decode('utf-8')

def generate_password(size: int = MIN_PASSWORD_SIZE) -> str:
    """Generate a high-entropy password."""
    return base64.urlsafe_b64encode(token_bytes(size)).decode('utf-8').rstrip('=')

def hmac_hash(salt: str, password: str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Generate an HMAC digest."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Invalid algorithm. Choose from: {', '.join(SUPPORTED_ALGORITHMS)}")
    
    hmac_obj = hmac.new(
        salt.encode('utf-8'),
        password.encode('utf-8'),
        getattr(hashlib, algorithm)()
    )
    return hmac_obj.hexdigest()

def pbkdf2_hash(password: str, salt: str, iterations: int, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Derive a key using PBKDF2-HMAC."""
    if algorithm == "sha256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "sha512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "blake2b":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm,
        length=64,  
        salt=binascii.unhexlify(salt),  
        iterations=iterations,
        backend=default_backend()
    )
    return base64.b64encode(kdf.derive(password.encode('utf-8'))).decode('utf-8')

def validate_username(username: str) -> str:
    """Validate username."""
    if not username.strip() or len(username) > 64 or '$' in username:
        raise ValueError("Invalid username")
    return username.strip()

def validate_manual_password(password: str) -> None:
    """Enforce password complexity."""
    if len(password) < MIN_MANUAL_PASSWORD_LENGTH:
        raise ValueError("Password must be at least 12 characters")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        raise ValueError("Password must contain uppercase and lowercase letters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")

def generate_rpcauth(username: str, password: str, salt: str, use_pbkdf2: bool, iterations: int, algorithm: str) -> Tuple[str, str]:
    """Generate RPC auth string."""
    hash_value = pbkdf2_hash(password, salt, iterations, algorithm) if use_pbkdf2 else hmac_hash(salt, password, algorithm)
    rpcauth = f"{username}:{salt}${hash_value}"
    return rpcauth, hash_value

def main():
    parser = argparse.ArgumentParser(description="Bitcoin RPC Auth Generator")
    parser.add_argument("username", help="Authentication username")
    parser.add_argument("password", nargs="?", help="Password or '-' for manual entry")
    parser.add_argument("-s", "--salt-size", type=int, default=MIN_SALT_SIZE, help="Salt size in bytes")
    parser.add_argument("-p", "--password-size", type=int, default=MIN_PASSWORD_SIZE, help="Generated password size")
    parser.add_argument("-a", "--algorithm", choices=SUPPORTED_ALGORITHMS, default=DEFAULT_ALGORITHM, help="Hash algorithm")
    parser.add_argument("-i", "--iterations", type=int, default=MIN_PBKDF2_ITERATIONS, help="PBKDF2 iterations")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--pbkdf2", action="store_true", help="Use PBKDF2-HMAC")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        username = validate_username(args.username)
    except ValueError as e:
        logger.error("Username error: %s", e)
        sys.exit(1)

    try:
        if args.password is None:
            password = generate_password(args.password_size)
        elif args.password == "-":
            password = getpass("Enter password: ").strip()
            validate_manual_password(password)
        else:
            password = args.password
            validate_manual_password(password)
    except ValueError as e:
        logger.error("Password error: %s", e)
        sys.exit(1)

    try:
        salt = generate_salt(args.salt_size)
    except ValueError as e:
        logger.error("Salt error: %s", e)
        sys.exit(1)

    try:
        rpcauth, hash_value = generate_rpcauth(username, password, salt, args.pbkdf2, args.iterations, args.algorithm)
    except ValueError as e:
        logger.error("Hash error: %s", e)
        sys.exit(1)

    output = {
        "username": username,
        "password": password,
        "rpcauth": rpcauth,
        "algorithm": args.algorithm,
        "salt": salt,
        "pbkdf2": args.pbkdf2,
        "iterations": args.iterations if args.pbkdf2 else None
    }

    if args.json:
        print(json.dumps(output, indent=4))
    else:
        print("\nBitcoin RPC Authentication:")
        print(f"rpcauth={rpcauth}")
        print(f"Password: {password}")
        print(f"Algorithm: {args.algorithm}")
        if args.pbkdf2:
            print(f"PBKDF2 Enabled with {args.iterations} iterations")
        else:
            print("HMAC only (consider --pbkdf2 for enhanced security)")

if __name__ == "__main__":
    main()
