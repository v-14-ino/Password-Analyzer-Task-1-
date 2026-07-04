"""
entropy.py — Password Entropy Calculator
------------------------------------------
Responsibility:
    - Calculates the information-theoretic entropy of a password,
      which measures its unpredictability/randomness in bits.
    - Uses character-pool entropy:
          Formula: H = L × log2(N)
          where L = password length, N = pool size
      The pool size N is determined by which character categories
      appear in the password (lowercase, uppercase, digits, symbols).

Character Set Sizes:
    Contains lowercase          → +26
    Contains uppercase          → +26
    Contains numbers            → +10
    Contains special characters → +32

Security Levels:
    Entropy < 35   → Very Weak
    35–50          → Weak
    50–65          → Medium
    65–80          → Strong
    80+            → Very Strong
"""

import math
import re


def calculate_entropy(password: str) -> dict:
    """
    Calculate the entropy of the entered password.

    Formula: entropy = length * log2(charset_size)

    Returns
    -------
    dict with keys:
        entropy        (float) - entropy rounded to 2 decimal places.
        charset_size   (int)   - size of the character pool used.
        security_level (str)   - human-readable security tier.
    """
    if not password:
        return {
            "entropy": 0.0,
            "charset_size": 0,
            "security_level": "Very Weak"
        }

    charset_size = _get_charset_size(password)
    if charset_size == 0:
        return {
            "entropy": 0.0,
            "charset_size": 0,
            "security_level": "Very Weak"
        }

    length = len(password)
    entropy_val = round(length * math.log2(charset_size), 2)
    security_level = _get_security_level(entropy_val)

    return {
        "entropy": entropy_val,
        "charset_size": charset_size,
        "security_level": security_level
    }


def _get_charset_size(password: str) -> int:
    """
    Determine the total character set size used by the password.
    """
    size = 0
    if re.search(r'[a-z]', password):          size += 26
    if re.search(r'[A-Z]', password):          size += 26
    if re.search(r'[0-9]', password):          size += 10
    if re.search(r'[^A-Za-z0-9]', password):   size += 32

    return size


def _get_security_level(entropy: float) -> str:
    """
    Map the entropy value to a security level tier.
    """
    if entropy < 35.0:
        return "Very Weak"
    if entropy < 50.0:
        return "Weak"
    if entropy < 65.0:
        return "Medium"
    if entropy < 80.0:
        return "Strong"
    return "Very Strong"
