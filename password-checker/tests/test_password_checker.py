"""Unit tests for password_checker.

Tests cover entropy calculation, pattern detection, character class
identification, and the integrated analysis pipeline. The HIBP network
call is mocked so tests run offline and deterministically.
"""

from __future__ import annotations

import math
from unittest.mock import patch

import password_checker
import pytest

# ----------------------------------------------------------------------------
# Character class detection
# ----------------------------------------------------------------------------

class TestCharacterClasses:
    def test_lowercase_only(self):
        size, has_lower, has_upper, has_digit, has_symbol = (
            password_checker.character_classes('abcdef')
        )
        assert has_lower is True
        assert has_upper is False
        assert has_digit is False
        assert has_symbol is False
        assert size == 26

    def test_all_classes(self):
        size, has_lower, has_upper, has_digit, has_symbol = (
            password_checker.character_classes('Abc123!@')
        )
        assert has_lower is True
        assert has_upper is True
        assert has_digit is True
        assert has_symbol is True
        assert size == 26 + 26 + 10 + 33

    def test_empty_password(self):
        size, *flags = password_checker.character_classes('')
        assert size == 0
        assert all(f is False for f in flags)

    def test_digits_only(self):
        size, has_lower, _has_upper, has_digit, _has_symbol = (
            password_checker.character_classes('12345')
        )
        assert has_digit is True
        assert has_lower is False
        assert size == 10


# ----------------------------------------------------------------------------
# Entropy calculation
# ----------------------------------------------------------------------------

class TestEntropy:
    def test_charset_entropy_zero_for_empty(self):
        assert password_checker.charset_entropy('', 26) == 0.0

    def test_charset_entropy_zero_for_zero_charset(self):
        assert password_checker.charset_entropy('abc', 0) == 0.0

    def test_charset_entropy_is_length_times_log2_charset(self):
        # 8 chars over a 26-char alphabet
        result = password_checker.charset_entropy('abcdefgh', 26)
        expected = 8 * math.log2(26)
        assert result == pytest.approx(expected)

    def test_shannon_entropy_zero_for_empty(self):
        assert password_checker.shannon_entropy('') == 0.0

    def test_shannon_entropy_zero_for_single_repeated_char(self):
        # 'aaaa' has zero per-character entropy
        assert password_checker.shannon_entropy('aaaa') == 0.0

    def test_shannon_entropy_max_for_unique_chars(self):
        # 'abcd' should have entropy = 4 * log2(4) = 8 bits
        result = password_checker.shannon_entropy('abcd')
        assert result == pytest.approx(8.0)

    def test_shannon_penalizes_repetition(self):
        # 'aabb' has less entropy than 'abcd'
        repeated = password_checker.shannon_entropy('aabb')
        unique = password_checker.shannon_entropy('abcd')
        assert repeated < unique


# ----------------------------------------------------------------------------
# Pattern detection
# ----------------------------------------------------------------------------

class TestPatternDetection:
    def test_detects_common_password(self):
        issues = password_checker.detect_patterns('password123')
        assert any('commonly-used' in i.lower() for i in issues)

    def test_detects_dictionary_word(self):
        issues = password_checker.detect_patterns('summer2024')
        assert any('dictionary' in i.lower() for i in issues)

    def test_detects_keyboard_sequence(self):
        issues = password_checker.detect_patterns('qwerty99')
        assert any('keyboard' in i.lower() for i in issues)

    def test_detects_repeated_characters(self):
        issues = password_checker.detect_patterns('aaaa1234')
        assert any('repeated' in i.lower() for i in issues)

    def test_detects_numeric_sequence(self):
        issues = password_checker.detect_patterns('hello1234')
        assert any('numeric sequence' in i.lower() for i in issues)

    def test_detects_alphabetical_sequence(self):
        issues = password_checker.detect_patterns('myabcdpass')
        assert any('alphabetical sequence' in i.lower() for i in issues)

    def test_detects_all_digits(self):
        issues = password_checker.detect_patterns('123456789')
        assert any('only digits' in i.lower() for i in issues)

    def test_detects_all_letters(self):
        issues = password_checker.detect_patterns('onlyletters')
        assert any('only letters' in i.lower() for i in issues)

    def test_detects_year_suffix(self):
        issues = password_checker.detect_patterns('MyPass2024')
        assert any('year' in i.lower() for i in issues)

    def test_detects_predictable_capitalization(self):
        issues = password_checker.detect_patterns('Password1')
        assert any('capitalization' in i.lower() for i in issues)

    def test_strong_password_has_no_issues(self):
        # Random-looking, no obvious patterns
        issues = password_checker.detect_patterns('xK9#mR2$pQ7&vL4@')
        assert len(issues) == 0


# ----------------------------------------------------------------------------
# Strength rating
# ----------------------------------------------------------------------------

class TestRateStrength:
    def test_common_password_is_very_weak(self):
        rating = password_checker.rate_strength(
            100.0,  # high entropy
            ['Matches a commonly-used password'],
        )
        assert rating == 'Very Weak'

    def test_low_entropy_is_very_weak(self):
        assert password_checker.rate_strength(20.0, []) == 'Very Weak'

    def test_medium_entropy_is_weak(self):
        assert password_checker.rate_strength(35.0, []) == 'Weak'

    def test_high_entropy_is_strong(self):
        assert password_checker.rate_strength(70.0, []) == 'Strong'

    def test_very_high_entropy_is_very_strong(self):
        assert password_checker.rate_strength(100.0, []) == 'Very Strong'


# ----------------------------------------------------------------------------
# Crack time estimates
# ----------------------------------------------------------------------------

class TestCrackTime:
    def test_zero_entropy_is_instant(self):
        assert password_checker.estimate_crack_time(0) == 'instant'

    def test_low_entropy_is_seconds(self):
        # 20 bits = ~1M guesses, at 10^11/sec = very fast
        result = password_checker.estimate_crack_time(20.0)
        assert 'second' in result.lower() or 'instant' in result.lower()

    def test_high_entropy_is_long_time(self):
        # 100 bits should be many years
        result = password_checker.estimate_crack_time(100.0)
        assert 'years' in result or 'centuries' in result or 'millennia' in result


# ----------------------------------------------------------------------------
# Integrated analysis
# ----------------------------------------------------------------------------

class TestAnalyzePassword:
    def test_weak_password_rated_very_weak(self):
        result = password_checker.analyze_password('password123')
        assert result.rating == 'Very Weak'
        assert len(result.issues) > 0

    def test_strong_password_rated_strong(self):
        result = password_checker.analyze_password('xK9#mR2$pQ7&vL4@nB8!')
        assert result.rating in ('Strong', 'Very Strong')

    def test_returns_length(self):
        result = password_checker.analyze_password('abc123')
        assert result.length == 6

    def test_returns_character_class_flags(self):
        result = password_checker.analyze_password('Abc123!')
        assert result.has_lower is True
        assert result.has_upper is True
        assert result.has_digit is True
        assert result.has_symbol is True

    def test_breach_check_not_called_by_default(self):
        result = password_checker.analyze_password('anypassword')
        assert result.breach_count is None


# ----------------------------------------------------------------------------
# Have I Been Pwned (mocked)
# ----------------------------------------------------------------------------

class TestHIBPCheck:
    def test_known_pwned_password_returns_count(self):
        """
        SHA-1 of 'password' is '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'.
        Prefix is '5BAA6', suffix is '1E4C9B93F3F0682250B6CF8331B7EE68FD8'.
        Simulate API returning that suffix with a count.
        """
        fake_response_body = (
            '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9999999\n'
            'OTHERHASHHASH:42\n'
        )

        with patch('password_checker.urllib_request.urlopen') as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = fake_response_body.encode('utf-8')

            count = password_checker.check_pwned('password')
            assert count == 9999999

    def test_unpwned_password_returns_zero(self):
        # API response that doesn't contain our suffix
        fake_response_body = (
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n'
            'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\n'
        )

        with patch('password_checker.urllib_request.urlopen') as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = fake_response_body.encode('utf-8')

            count = password_checker.check_pwned('somerandomthing')
            assert count == 0

    def test_network_failure_returns_none(self):
        from urllib.error import URLError

        with patch('password_checker.urllib_request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = URLError('network down')
            count = password_checker.check_pwned('password')
            assert count is None

    def test_only_hash_prefix_is_sent(self):
        """Verify k-anonymity: only the first 5 hash chars leave the machine."""
        with patch('password_checker.urllib_request.urlopen') as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = b''

            password_checker.check_pwned('password')

            # Inspect the Request object passed to urlopen
            call_args = mock_urlopen.call_args
            request_obj = call_args[0][0]
            url = request_obj.full_url

            # SHA-1 prefix for 'password' is '5BAA6'
            assert url.endswith('/range/5BAA6')

            # Extract the path component (everything after the last '/')
            # The domain itself contains 'password' (api.pwnedpasswords.com)
            # so we must check only the path, not the full URL
            path = url.rsplit('/', 1)[-1]
            assert path == '5BAA6'

            # The full hash should NEVER appear in the request
            full_hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
            assert full_hash not in url
