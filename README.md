# password-strength-auditor

A small, offline password strength auditor: estimates entropy, detects the usual
weak patterns (sequences, repeats, keyboard walks, common passwords) and returns
a 0–4 score with actionable feedback.

It runs entirely on your machine and never sends the password anywhere. It is a
teaching and policy-review tool, not a replacement for a real password manager or
a breach corpus.

## Features

- Entropy estimate based on character classes and length.
- Penalties for common passwords, sequences (`abcd`, `1234`), repeated blocks and
  keyboard rows.
- Score 0–4 with feedback lines.
- Reads from `--password` or stdin (`--stdin`) to avoid shell history.

## Installation

```bash
git clone https://github.com/victor-harden/password-strength-auditor.git
cd password-strength-auditor
```

## Usage

```bash
python3 auditor.py --password "correct horse battery staple"
echo "Tr0ub4dor&3" | python3 auditor.py --stdin
python3 auditor.py --password "password" --json
```

Exit codes: `0` score >= 3, `1` score < 3.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
