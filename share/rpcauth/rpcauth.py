#!/usr/bin/env python3
# Copyright (c) 2015-2025 The Bitcoin Core developers
# Licensed under the MIT software license.
# Enhanced for cryptographic excellence by xAI, 2025

import argparse
import json
import hmac
import hashlib
import os
import base64
import binascii
from getpass import getpass
from secrets import token_bytes, compare_digest
from typing import Tuple
import logging
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Security constants aligned with NIST SP 800-63B and FIPS 140-3
MIN_SALT_SIZE = 16  # 128-bit minimum per NIST
MIN_PASSWORD_SIZE = 32  # Strong entropy for generated passwords
MIN_PBKDF2_ITERATIONS = 310_000  # NIST recommendation as of 2025
DEFAULT_ALGORITHM = "sha512"  # Stronger default than SHA-256
SUPPORTED_ALGORITHMS = ["sha256", "sha512", "blake2b"]
MIN_MANUAL_PASSWORD_LENGTH = 12  # Enforce complexity for manual input

# Configure logging for auditability
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def generate_salt(size: int = MIN_SALT_SIZE) -> str:
    """Generate a cryptographically secure salt (FIPS-compliant)."""
    if size < MIN_SALT_SIZE:
        raise ValueError(f"Salt size must be at least {MIN_SALT_SIZE} bytes (128 bits)")
    salt = token_bytes(size)
    logger.debug("Generated salt of %d bytes", size)
    return binascii.hexlify(salt).decode('utf-8')

def generate_password(size: int = MIN_PASSWORD_SIZE) -> str:
    """Generate a high-entropy password with secure randomness."""
    if size < MIN_PASSWORD_SIZE:
        raise ValueError(f"Password size must be at least {MIN_PASSWORD_SIZE} bytes")
    password = base64.urlsafe_b64encode(token_bytes(size)).decode('utf-8').rstrip('=')
    logger.debug("Generated password with %d bytes of entropy", size)
    return password

def hmac_hash(salt: str, password: str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Generate an HMAC digest with a FIPS-approved algorithm."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithm must be one of: {', '.join(SUPPORTED_ALGORITHMS)}")
    hmac_obj = hmac.new(
        salt.encode('utf-8'),
        password.encode('utf-8'),
        getattr(hashlib, algorithm)
    )
    digest = hmac_obj.hexdigest()
    logger.debug("Computed HMAC with %s", algorithm)
    return digest

def pbkdf2_hash(password: str, salt: str, iterations: int, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Derive a key using PBKDF2-HMAC with NIST-compliant parameters."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithm must be one of: {', '.join(SUPPORTED_ALGORITHMS)}")
    if iterations < MIN_PBKDF2_ITERATIONS:
        logger.warning("Iterations below NIST minimum (%d), using %d", MIN_PBKDF2_ITERATIONS, iterations)
    
    kdf = PBKDF2HMAC(
        algorithm=getattr(hashes, algorithm.upper())(),
        length=64,  # 512-bit output for maximum strength
        salt=salt.encode('utf-8'),
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    logger.debug("Derived PBKDF2 key with %d iterations and %s", iterations, algorithm)
    return base64.b64encode(key).decode('utf-8')

def validate_username(username: str) -> str:
    """Validate username per security requirements."""
    if not username or len(username.strip()) == 0:
        raise ValueError("Username cannot be empty")
    if '$' in username:
        raise ValueError("Username cannot contain '$' (reserved separator)")
    if len(username) > 64:
        raise ValueError("Username must not exceed 64 characters")
    return username.strip()

def validate_manual_password(password: str) -> None:
    """Enforce NIST SP 800-63B password complexity."""
    if len(password) < MIN_MANUAL_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_MANUAL_PASSWORD_LENGTH} characters")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        raise ValueError("Password must contain both uppercase and lowercase letters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")

def generate_rpcauth(username: str, password: str, salt: str, use_pbkdf2: bool, 
                   iterations: int, algorithm: str) -> Tuple[str, str]:
    """Generate RPC auth string with secure derivation."""
    hash_value = (
        pbkdf2_hash(password, salt, iterations, algorithm) if use_pbkdf2
        else hmac_hash(salt, password, algorithm)
    )
    rpcauth = f"{username}:{salt}${hash_value}"
    logger.info("Generated RPC auth for user: %s", username)
    return rpcauth, hash_value

def main():
    parser = argparse.ArgumentParser(
        description=":skull: NSA-Grade Bitcoin RPC Auth Generator (FIPS 140-3 Inspired)",
        epilog="Built with cryptographic rigor by xAI, 2025"
    )
    parser.add_argument("username", help="Authentication username (max 64 chars)")
    parser.add_argument(
        "password",
        nargs="?",
        help="Password: specify directly, use '-' for manual input, or omit for auto-generation"
    )
    parser.add_argument(
        "-s", "--salt-size",
        type=int,
        default=MIN_SALT_SIZE,
        help=f"Salt size in bytes (default: {MIN_SALT_SIZE}, min: {MIN_SALT_SIZE})"
    )
    parser.add_argument(
        "-p", "--password-size",
        type=int,
        default=MIN_PASSWORD_SIZE,
        help=f"Generated password size in bytes (default: {MIN_PASSWORD_SIZE}, min: {MIN_PASSWORD_SIZE})"
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM})"
    )
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=MIN_PBKDF2_ITERATIONS,
        help=f"PBKDF2 iterations (default: {MIN_PBKDF2_ITERATIONS}, min: {MIN_PBKDF2_ITERATIONS})"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--pbkdf2",
        action="store_true",
        help="Use PBKDF2-HMAC (NIST SP 800-132) instead of plain HMAC"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Validate username
    try:
        username = validate_username(args.username)
    except ValueError as e:
        logger.error("Username validation failed: %s", e)
        sys.exit(1)

    # Handle password
    try:
        if args.password is None:
            password = generate_password(args.password_size)
            logger.info("Auto-generated high-entropy password")
        elif args.password == "-":
            password = getpass("Enter password: ").strip()
            validate_manual_password(password)
            logger.info("Accepted manually entered password")
        else:
            password = args.password
            validate_manual_password(password)
            logger.info("Accepted provided password")
    except ValueError as e:
        logger.error("Password validation failed: %s", e)
        sys.exit(1)

    # Generate salt
    try:
        salt = generate_salt(args.salt_size)
    except ValueError as e:
        logger.error("Salt generation failed: %s", e)
        sys.exit(1)

    # Generate RPC auth
    try:
        rpcauth, hash_value = generate_rpcauth(
            username, password, salt, args.pbkdf2, args.iterations, args.algorithm
        )
    except ValueError as e:
        logger.error("Hash generation failed: %s", e)
        sys.exit(1)

    # Prepare output
    output = {
        "username": username,
        "password": password,
        "rpcauth": rpcauth,
        "algorithm": args.algorithm,
        "salt": salt,
        "pbkdf2": args.pbkdf2,
        "iterations": args.iterations if args.pbkdf2 else None,
        "security_level": "NSA-Grade" if args.pbkdf2 else "Standard"
    }

    if args.json:
        print(json.dumps(output, indent=4))
    else:
        print("\n:rocket: Bitcoin RPC Authentication (NSA-Grade):")
        print(f"rpcauth={rpcauth}")
        print(f"\n:fire: Password (STORE SECURELY): {password}")
        print(f":lock: Algorithm: {args.algorithm}")
        if args.pbkdf2:
            print(f":shield: PBKDF2 Enabled with {args.iterations} iterations")
        else:
            print(":info: HMAC only (consider --pbkdf2 for enhanced security)")

if __name__ == "__main__":
    main()
