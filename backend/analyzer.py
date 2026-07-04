"""
analyzer.py — Core Password Analysis Orchestrator
---------------------------------------------------
Responsibility:
    - Acts as the central coordinator for all password analysis tasks.
    - Receives a raw password string and delegates to specialized modules:
        * entropy.py            → calculates information entropy / randomness
        * dictionary_checker.py → checks against known weak/common passwords
        * suggestions.py        → generates human-readable improvement tips
    - Combines all sub-results into a single structured response payload
      that is returned to app.py and ultimately sent to the frontend.

Module 2 additions:
    - LENGTH_MINIMUM    : int — minimum required password length (8).
    - LENGTH_RECOMMENDED: int — recommended password length (12).
    - check_password_length(password) — validates length, returns structured dict.

Module 3 additions:
    - check_uppercase(password)          → bool
    - check_lowercase(password)          → bool
    - check_numbers(password)            → bool
    - check_special_characters(password) → bool
    - analyze_character_diversity(password) → dict of all four results.

Module 4 additions:
    - check_dictionary_password(password) — checks against the common
      password list and returns a structured dict:
          { "is_common": bool, "matched_word": str|None, "message": str }

Module 6 additions:
    - calculate_score(password) — applies the exact scoring policy and returns:
          { "score": int, "classification": str, "progress": int }
    - _classify_score(score) — maps a numeric score to a classification label.

Scoring policy (max 100):
    Length ≥ 8                  : +20
    Length ≥ 12 (additional)    : +10
    Uppercase present           : +10
    Lowercase present           : +10
    Number present              : +10
    Special character present   : +10
    Not a common password       : +20
    Entropy ≥ 60 bits           : +10

Classification bands:
    0–39   → Weak
    40–69  → Medium
    70–89  → Strong
    90–100 → Very Strong

TODO (future steps):
    - Return a well-typed dict or dataclass as the full analysis result.
    - Add pattern-detection penalties (_check_patterns).
"""

import re
import secrets
import string
from entropy            import calculate_entropy
from dictionary_checker import is_common_password, find_common_match, contains_common_word
from crack_time         import estimate_crack_time

# ---------------------------------------------------------------------------
# Module 2 — Length Thresholds
# ---------------------------------------------------------------------------

# Changing these two constants updates every length-related check
# and message without touching the logic below.
LENGTH_MINIMUM     = 8   # Password is rejected below this threshold.
LENGTH_RECOMMENDED = 12  # Password is considered fully length-compliant here.


# ---------------------------------------------------------------------------
# Module 2 — Public: Length Check
# ---------------------------------------------------------------------------

def check_password_length(password: str) -> dict:
    """
    Validate the length of the given password against the minimum and
    recommended thresholds.

    Parameters
    ----------
    password : str
        The raw password string submitted by the user.

    Returns
    -------
    dict with keys:
        length             (int)  — character count of the password.
        minimum_required   (int)  — hard minimum (LENGTH_MINIMUM).
        recommended_length (int)  — recommended target (LENGTH_RECOMMENDED).
        passed             (bool) — True when length >= LENGTH_MINIMUM.
        message            (str)  — human-readable result description.
    """
    length  = len(password)
    passed  = length >= LENGTH_MINIMUM
    message = _build_length_message(length, passed)

    return {
        "length"            : length,
        "minimum_required"  : LENGTH_MINIMUM,
        "recommended_length": LENGTH_RECOMMENDED,
        "passed"            : passed,
        "message"           : message,
    }


# ---------------------------------------------------------------------------
# Module 2 — Private: Message Builder
# ---------------------------------------------------------------------------

def _build_length_message(length: int, passed: bool) -> str:
    """
    Return a human-readable explanation for the length check result.

    Kept separate from check_password_length() so message copy can be
    updated or localised without touching validation logic.

    Parameters
    ----------
    length : int  — actual password length.
    passed : bool — whether the minimum threshold was met.
    """
    if not passed:
        shortage = LENGTH_MINIMUM - length
        return (
            f"Password is too short ({length} chars). "
            f"Add at least {shortage} more character(s) to meet the minimum of {LENGTH_MINIMUM}."
        )
    if length < LENGTH_RECOMMENDED:
        return (
            f"Password length is acceptable ({length} chars), "
            f"but {LENGTH_RECOMMENDED} or more characters is recommended."
        )
    return f"Password length is acceptable ({length} chars)."


# ---------------------------------------------------------------------------
# Future Public Interface (placeholder — implemented in later modules)
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> dict:
    """
    Full analysis orchestrator — aggregates all individual checks.

    TODO (future steps):
        - Call check_password_length()
        - Call character-variety checks (uppercase, lowercase, digits, symbols)
        - Call entropy.calculate_entropy()
        - Call dictionary_checker.is_common_password()
        - Call suggestions.generate_suggestions()
        - Combine into a weighted overall score and rating
    """
    # Placeholder — returns minimal structure so importing is always safe.
    return {
        "score"      : 0,
        "rating"     : "Not Implemented",
        "entropy"    : 0.0,
        "is_common"  : False,
        "checks"     : {},
        "suggestions": [],
    }


# ---------------------------------------------------------------------------
# Module 3 — Public: Individual Character-Type Checks
# ---------------------------------------------------------------------------
# Each function answers a single yes/no question about the password.
# Keeping them separate means each can be called, tested, and documented
# independently without any coupling to the others.

def check_uppercase(password: str) -> bool:
    """Return True if the password contains at least one uppercase letter (A-Z)."""
    return bool(re.search(r'[A-Z]', password))


def check_lowercase(password: str) -> bool:
    """Return True if the password contains at least one lowercase letter (a-z)."""
    return bool(re.search(r'[a-z]', password))


def check_numbers(password: str) -> bool:
    """Return True if the password contains at least one digit (0-9)."""
    return bool(re.search(r'[0-9]', password))


def check_special_characters(password: str) -> bool:
    """Return True if the password contains at least one special character.

    Special characters are any printable ASCII symbols that are not
    letters or digits: ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
    """
    return bool(re.search(r'[^A-Za-z0-9]', password))


# ---------------------------------------------------------------------------
# Module 3 — Public: Character Diversity Aggregator
# ---------------------------------------------------------------------------

def analyze_character_diversity(password: str) -> dict:
    """
    Run all four character-type checks and return a single result dict.

    Each check is called exactly once through its dedicated function so
    that the logic remains in one place and is not duplicated here.

    Returns
    -------
    dict with keys:
        uppercase          (bool) — True if an A-Z letter is present.
        lowercase          (bool) — True if an a-z letter is present.
        numbers            (bool) — True if a digit 0-9 is present.
        special_characters (bool) — True if a non-alphanumeric char is present.
    """
    return {
        "uppercase"         : check_uppercase(password),
        "lowercase"         : check_lowercase(password),
        "numbers"           : check_numbers(password),
        "special_characters": check_special_characters(password),
    }


# ---------------------------------------------------------------------------
# Future Internal Helpers (stubs — implemented in later modules)
# ---------------------------------------------------------------------------

def _check_patterns(password: str) -> dict:
    """
    TODO (future module): Detect common weak patterns such as:
        - Sequential characters (abc, 123)
        - Keyboard walks (qwerty, asdf)
        - Repeated characters (aaaa, 1111)
    Return detected patterns and a penalty score.
    """
    pass


# ---------------------------------------------------------------------------
# Module 4 — Public: Dictionary Attack Check
# ---------------------------------------------------------------------------

def check_dictionary_password(password: str) -> dict:
    """
    Detect whether the password appears in the common password database.

    Delegates the O(1) set lookup to find_common_match() in
    dictionary_checker.py so that no file I/O or iteration occurs
    at request time — the set is already in memory.

    A dictionary attack works by trying every word in a pre-built list of
    common / previously breached passwords. This check flags passwords that
    would be cracked immediately by that technique.

    Parameters
    ----------
    password : str
        The raw password submitted by the user.

    Returns
    -------
    dict with keys:
        is_common       (bool)      — True if the password is in the common list.
        matched_word    (str|None)  — The matched entry (lowercased), or None.
        message         (str)       — Human-readable result explanation.
        contains_common (bool)      — True if the password contains a common word.
    """
    matched = find_common_match(password)
    is_common = matched is not None

    contained_word = contains_common_word(password)
    has_contained = contained_word is not None

    if is_common:
        message = (
            "This password is found in the common password database. "
            "It is highly vulnerable to dictionary attacks."
        )
    elif has_contained:
        message = (
            f"This password contains a common word ('{contained_word}') "
            "and is vulnerable to dictionary attacks."
        )
    else:
        message = "Password is not found in the common password database."

    return {
        "is_common"      : is_common,
        "matched_word"   : matched or contained_word,
        "message"        : message,
        "contains_common": has_contained,
    }


# ---------------------------------------------------------------------------
# Entropy Check Wrapper
# ---------------------------------------------------------------------------

def check_entropy(password: str) -> dict:
    """
    Calculate entropy value, character pool size, and security level tier.
    """
    return calculate_entropy(password)


# ---------------------------------------------------------------------------
# Crack Time Estimation Wrapper
# ---------------------------------------------------------------------------

def check_crack_time(password: str) -> dict:
    """
    Estimate the crack time of the password based on its entropy.
    """
    # Reuse entropy calculation without duplication
    entropy_data = calculate_entropy(password)
    return estimate_crack_time(entropy_data["entropy"])


# ---------------------------------------------------------------------------
# Module 6 — Public: Strength Score
# ---------------------------------------------------------------------------

# Scoring policy constants — change here to update the entire scoring system.
_SCORE_LENGTH_MINIMUM     = 20   # awarded when length >= LENGTH_MINIMUM (8)
_SCORE_LENGTH_RECOMMENDED = 10   # additional points when length >= LENGTH_RECOMMENDED (12)
_SCORE_UPPERCASE          = 10   # uppercase letter present
_SCORE_LOWERCASE          = 10   # lowercase letter present
_SCORE_NUMBER             = 10   # digit present
_SCORE_SPECIAL            = 10   # special character present
_SCORE_NOT_COMMON         = 20   # password NOT in the common list
_SCORE_ENTROPY_BONUS      = 10   # awarded when entropy >= 60 bits

_ENTROPY_BONUS_THRESHOLD  = 60.0 # bits — threshold for the entropy bonus point


def calculate_score(password: str) -> dict:
    """
    Calculate a numeric strength score for the password using a robust scoring policy.

    The score is calculated out of 100 points, consisting of 4 components (max 25 points each):
        1. Length (max 25):
           - length < 8: 0 points
           - 8 <= length < 12: 15 points
           - length >= 12: 25 points
        2. Character diversity (max 25):
           - 1 category present: 5 points
           - 2 categories present: 12 points
           - 3 categories present: 18 points
           - 4 categories present: 25 points
        3. Entropy (max 25):
           - entropy >= 60 bits: 25 points
           - entropy < 60 bits: scaled linearly (entropy / 60.0) * 25
        4. Dictionary check (max 25):
           - exact match with a common password: 0 points
           - contains a common password as a substring (>= 4 chars): 10 points (loses significant points)
           - not in the database and doesn't contain common words: 25 points

    The score is calculated only from the sub-analysis results (the analysis object).
    If any required character category is missing, the score is significantly reduced,
    and capped so that it can never be classified as "Very Strong".

    Classification bands:
        0–39   → Weak
        40–69  → Medium
        70–89  → Strong
        90–100 → Very Strong

    Parameters
    ----------
    password : str
        The raw password string submitted by the user.

    Returns
    -------
    dict with keys:
        score          (int) — total points earned (0–100).
        classification (str) — human-readable band label.
        progress       (int) — same as score; used by the frontend progress bar.
    """
    if not password:
        return {
            "score": 0,
            "classification": "Weak",
            "progress": 0
        }

    # Construct the analysis object first
    analysis = {
        "length_check": check_password_length(password),
        "diversity_check": analyze_character_diversity(password),
        "dictionary_check": check_dictionary_password(password),
        "entropy_bits": calculate_entropy(password)
    }

    # 1. Length Score (max 25)
    length = analysis["length_check"]["length"]
    if length < 8:
        length_score = 0
    elif length < 12:
        length_score = 15
    else:
        length_score = 25

    # 2. Diversity Score (max 25)
    categories = 0
    div = analysis["diversity_check"]
    if div["uppercase"]:          categories += 1
    if div["lowercase"]:          categories += 1
    if div["numbers"]:            categories += 1
    if div["special_characters"]: categories += 1

    if categories == 1:
        diversity_score = 5
    elif categories == 2:
        diversity_score = 12
    elif categories == 3:
        diversity_score = 18
    elif categories == 4:
        diversity_score = 25
    else:
        diversity_score = 0

    # 3. Entropy Score (max 25)
    entropy_bits = analysis["entropy_bits"]["entropy"]
    if entropy_bits >= 60.0:
        entropy_score = 25
    else:
        entropy_score = max(0, min(25, round((entropy_bits / 60.0) * 25)))

    # 4. Dictionary Score (max 25)
    dict_res = analysis["dictionary_check"]
    if dict_res["is_common"]:
        dictionary_score = 0
    elif dict_res.get("contains_common", False):
        dictionary_score = 10
    else:
        dictionary_score = 25

    # Base score sum
    score = length_score + diversity_score + entropy_score + dictionary_score

    # If any required category is missing: significantly reduce score and prevent "Very Strong"
    if categories < 4:
        score -= 15  # significant reduction
        score = min(score, 85)  # cap at 85 to ensure classification cannot be Very Strong (90+)

    score = max(0, min(100, score))

    return {
        "score"          : score,
        "classification" : _classify_score(score),
        "progress"       : score,
    }



# ---------------------------------------------------------------------------
# Module 6 — Private: Score Classification
# ---------------------------------------------------------------------------

def _classify_score(score: int) -> str:
    """
    Map a numeric score (0–100) to a human-readable classification label.

    Classification bands:
        0–39   → "Weak"
        40–69  → "Medium"
        70–89  → "Strong"
        90–100 → "Very Strong"

    Kept separate from calculate_score() so the bands can be adjusted
    without touching the scoring arithmetic.

    Parameters
    ----------
    score : int — numeric score in the range 0–100.

    Returns
    -------
    str — one of: "Weak", "Medium", "Strong", "Very Strong".
    """
    if score >= 90: return "Very Strong"
    if score >= 70: return "Strong"
    if score >= 40: return "Medium"
    return "Weak"


# ---------------------------------------------------------------------------
# Password Generator
# ---------------------------------------------------------------------------

def generate_secure_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password of specified length.

    Ensures at least one character from each of:
      - Uppercase (A-Z)
      - Lowercase (a-z)
      - Number (0-9)
      - Special character (printable ASCII punctuation)

    Uses secrets module for cryptographically strong random generation.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 to ensure character diversity.")

    # Define the character sets
    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    digits = string.digits
    specials = string.punctuation

    # Ensure at least one from each category
    password_chars = [
        secrets.choice(uppers),
        secrets.choice(lowers),
        secrets.choice(digits),
        secrets.choice(specials)
    ]

    # Fill the rest with randomly chosen characters from all pools combined
    all_chars = uppers + lowers + digits + specials
    password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle the characters cryptographically in-place using secrets.SystemRandom()
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)

