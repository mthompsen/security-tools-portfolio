#!/usr/bin/env python3
"""
password_checker.py - Password strength analysis tool.

Analyzes a password using:
  - Shannon entropy estimation (bits of randomness)
  - Length-based scoring
  - Character class diversity
  - Pattern detection (sequences, repetitions, dictionary words)
  - Optional Have I Been Pwned check (k-anonymity API, never sends the
    full password)

Usage:
  python password_checker.py                          # interactive (hidden input)
  python password_checker.py --password 'p4ssword!'   # direct (not recommended)
  python password_checker.py --check-breach           # also query HIBP
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import sys
from dataclasses import dataclass, field
from urllib import request as urllib_request
from urllib.error import URLError

# ----------------------------------------------------------------------------
# Pattern definitions
# ----------------------------------------------------------------------------

# A small, illustrative list. Real systems use much larger lists
# (rockyou.txt has 14M entries). This is enough to catch obvious bad picks.
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'qwerty123', 'abc123', 'letmein', 'welcome', 'welcome1',
    'admin', 'admin123', 'root', 'toor', 'changeme', 'iloveyou',
    'monkey', 'dragon', 'master', 'football', 'baseball', 'starwars',
    'princess', 'sunshine', 'login', 'guest', 'test', 'test123',
    'passw0rd', 'p@ssw0rd', 'p@ssword', '1q2w3e4r', 'qazwsx',
    'trustno1', 'access', 'shadow', 'superman', 'batman',
}

# Common dictionary roots that get prepended/appended with numbers and symbols
DICTIONARY_ROOTS = {
    'password', 'admin', 'love', 'welcome', 'hello', 'summer', 'winter',
    'spring', 'autumn', 'monkey', 'dragon', 'sunshine', 'football',
    'baseball', 'computer', 'internet', 'security', 'shadow',
}

# Keyboard sequences (lowercase)
KEYBOARD_SEQUENCES = [
    'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'asdfghjkl',
    'zxcv', 'zxcvbn', 'zxcvbnm', '12345', '123456', '1234567890',
    'abcdef', 'abcdefg', 'qaz', 'wsx', 'edc', '!@#$', '!@#$%',
]


# ----------------------------------------------------------------------------
# Result type
# ----------------------------------------------------------------------------

@dataclass
class StrengthResult:
    length: int = 0
    entropy_bits: float = 0.0
    charset_size: int = 0
    has_lower: bool = False
    has_upper: bool = False
    has_digit: bool = False
    has_symbol: bool = False
    issues: list[str] = field(default_factory=list)
    breach_count: int | None = None  # None if not checked
    rating: str = ''
    crack_time_estimate: str = ''


# ----------------------------------------------------------------------------
# Core analysis
# ----------------------------------------------------------------------------

def character_classes(password: str) -> tuple[int, bool, bool, bool, bool]:
    """Return (effective_charset_size, has_lower, has_upper, has_digit, has_symbol)."""
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_symbol:
        size += 33  # rough estimate for printable symbols
    return size, has_lower, has_upper, has_digit, has_symbol


def shannon_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password as a string."""
    if not password:
        return 0.0
    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length  # total bits, not per-character


def charset_entropy(password: str, charset_size: int) -> float:
    """
    Estimate entropy assuming each character is independently drawn from a
    charset of the given size. This is the optimistic upper bound used in
    most strength calculators.
    """
    if charset_size <= 0 or not password:
        return 0.0
    return len(password) * math.log2(charset_size)


def detect_patterns(password: str) -> list[str]:
    """Look for common weak patterns. Returns a list of issue descriptions."""
    issues: list[str] = []
    lower = password.lower()

    # Exact match against common password list
    if lower in COMMON_PASSWORDS:
        issues.append('Matches a commonly-used password')

    # Contains a dictionary root
    for root in DICTIONARY_ROOTS:
        if root in lower and len(root) >= 5:
            issues.append(f'Contains dictionary word: "{root}"')
            break  # don't pile on

    # Keyboard walk
    for seq in KEYBOARD_SEQUENCES:
        if seq in lower and len(seq) >= 4:
            issues.append(f'Contains keyboard sequence: "{seq}"')
            break

    # Repeated character runs (e.g., "aaaa", "1111")
    if re.search(r'(.)\1{3,}', password):
        issues.append('Contains a run of 4+ repeated characters')

    # Sequential digits (e.g., "1234", "5678")
    if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789)', password):
        issues.append('Contains a numeric sequence (1234, etc.)')

    # Sequential letters
    sequential_letters = [
        'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij',
    ]
    for seq in sequential_letters:
        if seq in lower:
            issues.append('Contains an alphabetical sequence (abcd, etc.)')
            break

    # All-digit password
    if password.isdigit():
        issues.append('Contains only digits')

    # All-alpha password
    if password.isalpha():
        issues.append('Contains only letters')

    # Year pattern (1900-2099) at end — very common suffix
    if re.search(r'(?:19|20)\d{2}$', password):
        issues.append('Ends with a year (common pattern)')

    # Simple capitalization (capital first letter, rest lowercase + digits/symbols)
    if re.fullmatch(r'[A-Z][a-z]+[\d\W]*', password):
        issues.append('Uses predictable capitalization pattern')

    return issues


def estimate_crack_time(entropy_bits: float) -> str:
    """Rough estimate assuming 10^11 guesses/second (modern offline attack)."""
    if entropy_bits <= 0:
        return 'instant'
    # Average crack = half the keyspace
    guesses = 2 ** (entropy_bits - 1)
    seconds = guesses / 1e11

    units = [
        ('millennia', 1000 * 365.25 * 86400),
        ('centuries', 100 * 365.25 * 86400),
        ('years', 365.25 * 86400),
        ('months', 30 * 86400),
        ('days', 86400),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1),
    ]
    for name, divisor in units:
        if seconds >= divisor:
            value = seconds / divisor
            if value >= 1e9:
                return f'{value:.2e} {name}'
            if value >= 100:
                return f'{value:,.0f} {name}'
            if value >= 10:
                return f'{value:.1f} {name}'
            return f'{value:.2f} {name}'
    return 'less than a second'


def rate_strength(entropy_bits: float, issues: list[str]) -> str:
    """Map entropy + issues to a qualitative rating."""
    if issues and any('commonly-used' in i for i in issues):
        return 'Very Weak'
    if entropy_bits < 28:
        return 'Very Weak'
    if entropy_bits < 40:
        return 'Weak'
    if entropy_bits < 60:
        return 'Reasonable'
    if entropy_bits < 80:
        return 'Strong'
    return 'Very Strong'


# ----------------------------------------------------------------------------
# Have I Been Pwned (k-anonymity)
# ----------------------------------------------------------------------------

def check_pwned(password: str, timeout: float = 5.0) -> int | None:
    """
    Check the password against the HIBP Pwned Passwords corpus using the
    k-anonymity API. The full password is never transmitted: only the
    first 5 characters of its SHA-1 hash are sent, and the API returns
    all matching suffixes for us to check locally.

    Returns the breach count if found, 0 if not found, or None on error.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'

    req = urllib_request.Request(
        url,
        headers={
            'User-Agent': 'password-checker-portfolio-tool',
            'Add-Padding': 'true',
        },
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8')
    except URLError as e:
        print(f'[hibp check failed: {e}]', file=sys.stderr)
        return None
    except Exception as e:
        print(f'[hibp check failed: {e}]', file=sys.stderr)
        return None

    for line in body.splitlines():
        if ':' not in line:
            continue
        line_suffix, count_str = line.split(':', 1)
        if line_suffix.strip().upper() == suffix:
            try:
                return int(count_str.strip())
            except ValueError:
                return None
    return 0


# ----------------------------------------------------------------------------
# Top-level analysis
# ----------------------------------------------------------------------------

def analyze_password(password: str, check_breach: bool = False) -> StrengthResult:
    """Run the full analysis suite on a password."""
    result = StrengthResult(length=len(password))

    charset_size, has_lower, has_upper, has_digit, has_symbol = character_classes(password)
    result.charset_size = charset_size
    result.has_lower = has_lower
    result.has_upper = has_upper
    result.has_digit = has_digit
    result.has_symbol = has_symbol

    # Use the smaller of charset-based vs shannon-based entropy
    # (charset is optimistic; shannon penalizes character reuse)
    charset_e = charset_entropy(password, charset_size)
    shannon_e = shannon_entropy(password)
    result.entropy_bits = min(charset_e, shannon_e) if password else 0.0

    # Pattern penalties
    result.issues = detect_patterns(password)
    # Apply penalty: each detected issue knocks off ~10 bits
    effective_entropy = result.entropy_bits - 10 * len(result.issues)
    effective_entropy = max(0.0, effective_entropy)

    result.crack_time_estimate = estimate_crack_time(effective_entropy)
    result.rating = rate_strength(effective_entropy, result.issues)

    if check_breach:
        result.breach_count = check_pwned(password)

    return result


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------

def report(result: StrengthResult) -> None:
    print('=' * 70)
    print('PASSWORD STRENGTH ANALYSIS')
    print('=' * 70)
    print()

    print(f'  Length:           {result.length} characters')
    print(f'  Character pool:   {result.charset_size} possible characters')
    print('  Character types: ', end='')
    types = []
    if result.has_lower:
        types.append('lowercase')
    if result.has_upper:
        types.append('uppercase')
    if result.has_digit:
        types.append('digits')
    if result.has_symbol:
        types.append('symbols')
    print(', '.join(types) if types else '(none)')

    print(f'  Entropy estimate: {result.entropy_bits:.1f} bits')
    print(f'  Rating:           {result.rating}')
    print(f'  Crack time est:   {result.crack_time_estimate}')
    print('                    (offline attack @ 10^11 guesses/sec)')
    print()

    if result.issues:
        print('Issues detected:')
        print('-' * 70)
        for issue in result.issues:
            print(f'  - {issue}')
        print()

    if result.breach_count is not None:
        print('Have I Been Pwned check:')
        print('-' * 70)
        if result.breach_count == 0:
            print('  Not found in known breach corpus.')
        else:
            print(f'  FOUND in known breaches: {result.breach_count:,} occurrences')
            print('  This password has appeared in data breaches and should')
            print('  not be used anywhere. Change it immediately if in use.')
        print()

    print('Recommendations:')
    print('-' * 70)
    if result.length < 12:
        print('  - Use at least 12 characters (16+ recommended)')
    if not (result.has_lower and result.has_upper and result.has_digit and result.has_symbol):
        print('  - Mix uppercase, lowercase, digits, and symbols')
    if result.issues:
        print('  - Avoid common words, sequences, and predictable patterns')
    if result.rating in ('Very Weak', 'Weak', 'Reasonable'):
        print('  - Consider a passphrase: 4+ random words joined together')
        print('    (e.g., "correct-horse-battery-staple-clip-fence")')
    print('  - Use a password manager (Bitwarden, 1Password, KeePassXC)')
    print('  - Enable multi-factor authentication wherever available')
    print()


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Analyze password strength using entropy and pattern detection.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python password_checker.py                 # prompt for password (hidden)\n'
            '  python password_checker.py --check-breach  # also check HIBP\n'
            '\n'
            'Note: --password is provided for scripting but exposes the password\n'
            'in your shell history and process list. Use the interactive prompt\n'
            'when analyzing real passwords.'
        ),
    )
    parser.add_argument(
        '--password',
        help='Password to analyze (not recommended; use interactive prompt).',
    )
    parser.add_argument(
        '--check-breach',
        action='store_true',
        help='Query Have I Been Pwned (k-anonymity, password never sent).',
    )

    args = parser.parse_args()

    if args.password is not None:
        password = args.password
    else:
        try:
            password = getpass.getpass('Password to analyze: ')
        except (EOFError, KeyboardInterrupt):
            print()
            return 1

    if not password:
        print('error: empty password', file=sys.stderr)
        return 1

    result = analyze_password(password, check_breach=args.check_breach)
    report(result)
    return 0


if __name__ == '__main__':
    sys.exit(main())
