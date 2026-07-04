"""
dictionary_checker.py — Common Password Dictionary Checker
------------------------------------------------------------
Responsibility:
    - Loads the list of commonly used / breached passwords from
      'common_passwords.txt' once at module import time into an
      in-memory set for O(1) average-case lookup.
    - Exposes is_common_password(password) which performs a
      case-insensitive comparison against that set.
    - Protects against trivially guessable passwords that would
      otherwise score well on character-variety metrics
      (e.g., "Password1!").

Module 4 additions:
    - find_common_match(password) — returns the matched lowercased word
      from the set, or None if the password is not common.
      Used by analyzer.check_dictionary_password() to surface which
      specific entry was matched, so the UI can display it.

Module 6 additions:
    - load_common_passwords() — reads the file, strips comments and
      blank lines, lowercases entries, returns a frozenset.
    - _COMMON_PASSWORDS_SET — module-level cache populated at import.
    - is_common_password(password) — case-insensitive membership test.

TODO (future steps):
    - Implement basic leet-speak normalization in _normalize()
      (e.g., "p4ssw0rd" → "password") before the lookup.
    - Ship a larger word list (millions of entries from HIBP / SecLists).
"""

import os

# ---------------------------------------------------------------------------
# Module-level constant — path to the word list file
# ---------------------------------------------------------------------------

# Resolve relative to this file so it works regardless of the working
# directory from which app.py is launched.
_COMMON_PASSWORDS_FILE = os.path.join(
    os.path.dirname(__file__), "common_passwords.txt"
)


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def load_common_passwords() -> frozenset:
    """
    Read common_passwords.txt and return a frozenset of lowercased entries.

    Lines starting with '#' and blank lines are ignored.
    The frozenset is immutable, hashable, and slightly faster for repeated
    membership tests than a regular set.

    Returns
    -------
    frozenset of str
        Lowercased password strings. Empty frozenset if the file is missing.
    """
    entries: list[str] = []

    try:
        with open(_COMMON_PASSWORDS_FILE, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                # Skip comment lines and blank lines
                if not stripped or stripped.startswith("#"):
                    continue
                entries.append(stripped.lower())

    except FileNotFoundError:
        # Log a warning but do not crash — the module stays safely importable.
        print(
            f"[WARNING] dictionary_checker: '{_COMMON_PASSWORDS_FILE}' not found. "
            "Common-password checks will be skipped."
        )

    return frozenset(entries)


# ---------------------------------------------------------------------------
# Module-level cache — populated once at import time
# ---------------------------------------------------------------------------

# Loading at import time keeps is_common_password() a pure O(1) lookup.
# The file is small (< 100 KB even for large lists), so startup cost is negligible.
_COMMON_PASSWORDS_SET: frozenset = load_common_passwords()


def is_common_password(password: str) -> bool:
    """
    Check whether the given password appears in the common passwords list.

    The comparison is case-insensitive: "Password", "PASSWORD", and
    "password" all match the entry "password" in the list.

    Parameters
    ----------
    password : str
        The raw password submitted by the user.

    Returns
    -------
    bool
        True  — password (lowercased) is in the common list.
        False — password does not appear in the list.
    """
    if not password:
        return False
    return password.lower() in _COMMON_PASSWORDS_SET


# ---------------------------------------------------------------------------
# Module 4 — Public: Match Retrieval
# ---------------------------------------------------------------------------

def find_common_match(password: str) -> str | None:
    """
    Return the matched entry from the common passwords set, or None.

    Builds on is_common_password() by surfacing *which* word was matched
    so that callers (analyzer.check_dictionary_password) can include the
    specific matched word in their response payload.

    The lookup is O(1) — same cost as a plain membership test — because
    Python sets store items by hash; retrieving the canonical entry just
    requires a single hash lookup.

    Parameters
    ----------
    password : str
        The raw password submitted by the user.

    Returns
    -------
    str | None
        The lowercased matched entry if found, None otherwise.

    Examples
    --------
    >>> find_common_match("PASSWORD")
    'password'
    >>> find_common_match("MyUnique$ecret99!")
    None
    """
    if not password:
        return None

    normalized = password.lower()
    if normalized in _COMMON_PASSWORDS_SET:
        return normalized   # the set already stores lowercased entries

    return None


def contains_common_word(password: str) -> str | None:
    """
    Check if the password contains any common password from the database as a substring.

    To avoid false positives on tiny words, we only check dictionary words
    that are at least 4 characters long.

    This is optimized to run in O(L^2) time where L is the password length,
    rather than O(N) where N is the dictionary size. It prevents CPU starvation
    and Denial of Service (DoS) vulnerability.

    Parameters
    ----------
    password : str
        The raw password.

    Returns
    -------
    str | None
        The lowercased matched common word if found, None otherwise.
    """
    if not password:
        return None

    normalized = password.lower()
    n_len = len(normalized)

    # Search starting with the longest possible substrings down to length 4
    for length in range(n_len, 3, -1):
        for start in range(n_len - length + 1):
            substring = normalized[start:start+length]
            if substring in _COMMON_PASSWORDS_SET:
                return substring

    return None


# ---------------------------------------------------------------------------
# Internal Helpers (future — not yet active)
# ---------------------------------------------------------------------------

def _normalize(password: str) -> str:
    """
    TODO: Normalize a password before comparison:
        - Convert to lowercase
        - Replace common leet-speak substitutions
          (0→o, 3→e, 1→l, 4→a, @→a, $→s, etc.)
    This catches variants like "P4ssw0rd!" that bypass naive string matching.
    """
    pass
