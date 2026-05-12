# password-checker

Password strength analyzer using entropy calculation, character class analysis, common-pattern detection, and optional integration with the Have I Been Pwned breach corpus.

## Usage

```bash
# Interactive (hidden input, recommended for real passwords)
python password_checker.py

# Also check against Have I Been Pwned
python password_checker.py --check-breach

# Direct (for scripting; NOT recommended for real passwords)
python password_checker.py --password 'TestPassword123!'
```

### Arguments

| Flag | Description |
|------|-------------|
| `--password` | Password to analyze. Exposes password in shell history and process list. Use the interactive prompt for real passwords. |
| `--check-breach` | Query Have I Been Pwned via k-anonymity API. |

## How it works

### Entropy calculation

The tool computes two entropy estimates and uses the more conservative one:

1. **Charset-based entropy**: `length × log₂(charset_size)` — optimistic upper bound that assumes each character is independently random.
2. **Shannon entropy**: Measures the actual information content based on character frequency distribution in the password. Penalizes character reuse.

### Pattern detection

Beyond raw entropy, the tool penalizes detectable structure:

- Exact matches against a list of common passwords (`password123`, `qwerty`, etc.)
- Dictionary words embedded in the password
- Keyboard sequences (`qwerty`, `asdfgh`, `1234`)
- Character repetitions (`aaaa`, `1111`)
- Numeric sequences (`1234`, `5678`)
- Alphabetical sequences (`abcd`, `efgh`)
- All-digit or all-letter passwords
- Year suffixes (`2024`, `1985`)
- Predictable capitalization patterns (`Password1!`)

Each detected issue subtracts ~10 bits from the effective entropy score.

### Have I Been Pwned check

When `--check-breach` is enabled, the tool queries the [HIBP Pwned Passwords API](https://haveibeenpwned.com/Passwords) using k-anonymity:

1. SHA-1 hash the password locally
2. Send only the first 5 characters of the hash to the API
3. API returns all known passwords whose hash starts with that prefix
4. Tool checks locally whether the full hash is in the returned list

**Your password is never transmitted to a remote server.** Only the 5-character hash prefix leaves your machine.

### Crack time estimate

Estimates the time to brute-force the password offline, assuming a modern attacker capable of 10¹¹ guesses per second (achievable with consumer GPU clusters against weak hashing algorithms). This is an approximation, not a guarantee.

## Sample output

```
======================================================================
PASSWORD STRENGTH ANALYSIS
======================================================================

  Length:           14 characters
  Character pool:   95 possible characters
  Character types:  lowercase, uppercase, digits, symbols
  Entropy estimate: 91.9 bits
  Rating:           Very Strong
  Crack time est:   1.10e+09 years
                    (offline attack @ 10^11 guesses/sec)

Have I Been Pwned check:
----------------------------------------------------------------------
  Not found in known breach corpus.

Recommendations:
----------------------------------------------------------------------
  - Use a password manager (Bitwarden, 1Password, KeePassXC)
  - Enable multi-factor authentication wherever available
```

## Rating scale

| Rating | Effective Entropy |
|--------|-------------------|
| Very Weak | <28 bits |
| Weak | 28–40 bits |
| Reasonable | 40–60 bits |
| Strong | 60–80 bits |
| Very Strong | ≥80 bits |

Any match against a common password automatically downgrades to **Very Weak** regardless of entropy.

## Limitations

This is a learning tool. Production-grade analyzers like [zxcvbn](https://github.com/dropbox/zxcvbn) implement more sophisticated heuristics including:

- Per-language dictionary databases (millions of words)
- L33t-speak normalization (`p@ssw0rd` → `password`)
- Date pattern recognition with calendar awareness
- Repeat and sequence detection with token-level analysis
- Markov chain models for natural-language likelihood

For real applications, use zxcvbn or a similar library rather than rolling your own.

## Security notes

- The tool **does not log, save, or transmit passwords** anywhere
- The HIBP check uses k-anonymity and never sends the full password
- The interactive prompt uses `getpass` to suppress terminal echo
- For maximum safety, run on a trusted local machine, not over SSH or in a shared environment

## Extension ideas

- Integrate with `zxcvbn-python` for higher-quality scoring
- Add passphrase strength analysis with word-list entropy
- Generate strong password suggestions
- Output to JSON for integration with password policy enforcement tools
- Add support for batch analysis of a password file (with appropriate access controls)

## Requirements

Python 3.10+, no external dependencies (uses only the standard library). The HIBP check uses `urllib` from the standard library, not `requests`.
