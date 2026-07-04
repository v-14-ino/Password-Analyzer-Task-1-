"""
crack_time.py — Estimated Brute-Force Crack Time Calculator
-----------------------------------------------------------
Responsibility:
    - Converts a password's entropy value into an estimated crack time
      under a standard brute-force threat model.
    - Threat model:
          Attacker guesses/hashes per second = 1,000,000,000 (1 billion)
          Possible combinations = 2 ^ entropy
          Average guesses to crack = combinations / 2
          Estimated time = average guesses / guesses_per_second (in seconds)
    - Formats the estimated time into a human-readable string.
"""

import math


def estimate_crack_time(entropy: float) -> dict:
    """
    Convert password entropy into an estimated brute-force crack time.

    Parameters
    ----------
    entropy : float
        The entropy value of the password.

    Returns
    -------
    dict with keys:
        entropy              (float) - input entropy value.
        estimated_crack_time (str)   - human-readable time estimation string.
    """
    if entropy <= 0.0:
        return {
            "entropy": 0.0,
            "estimated_crack_time": "Instantly"
        }

    # 1. Possible combinations = 2^entropy
    try:
        combinations = math.pow(2.0, entropy)
    except OverflowError:
        # For extremely high entropy values, cap at a huge representation
        return {
            "entropy": entropy,
            "estimated_crack_time": "Trillions of Years"
        }

    # 2. Average guesses = combinations / 2
    average_guesses = combinations / 2.0

    # 3. Estimated time = average guesses / guesses_per_second
    guesses_per_second = 1_000_000_000.0  # 1 Billion guesses/sec
    seconds = average_guesses / guesses_per_second

    # 4. Format into human-readable string
    readable_time = _format_seconds(seconds)

    return {
        "entropy": entropy,
        "estimated_crack_time": readable_time
    }


def _format_seconds(seconds: float) -> str:
    """
    Convert a duration in seconds into a friendly human-readable format.
    """
    if seconds < 1.0:
        return "Instantly"

    # Seconds
    if seconds < 60.0:
        val = round(seconds)
        return f"{val} Second" if val == 1 else f"{val} Seconds"

    # Minutes
    minutes = seconds / 60.0
    if minutes < 60.0:
        val = round(minutes)
        return f"{val} Minute" if val == 1 else f"{val} Minutes"

    # Hours
    hours = minutes / 60.0
    if hours < 24.0:
        val = round(hours)
        return f"{val} Hour" if val == 1 else f"{val} Hours"

    # Days
    days = hours / 24.0
    if days < 30.0:
        val = round(days)
        return f"{val} Day" if val == 1 else f"{val} Days"

    # Months
    months = days / 30.0
    if months < 12.0:
        val = round(months)
        return f"{val} Month" if val == 1 else f"{val} Months"

    # Years
    years = days / 365.0
    if years < 1_000_000.0:
        val = round(years)
        return f"{val} Year" if val == 1 else f"{val:,} Years"

    # Millions of Years
    million_years = years / 1_000_000.0
    if million_years < 1000.0:
        val = round(million_years, 1)
        return f"{val} Million Years"

    # Billions of Years
    billion_years = million_years / 1000.0
    val = round(billion_years, 1)
    return f"{val} Billion Years"
