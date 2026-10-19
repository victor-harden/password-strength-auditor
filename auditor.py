#!/usr/bin/env python3
"""Offline password strength auditor."""
from __future__ import annotations

import argparse
import json
import math
import re
import sys

COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein", "monkey",
    "dragon", "111111", "iloveyou", "admin", "welcome", "login", "passw0rd",
    "sunshine", "princess", "football", "charlie", "donald", "master", "shadow",
    "superman", "michael", "jennifer", "hunter2", "trustno1", "000000", "qwerty123",
    "1q2w3e4r", "zxcvbnm", "starwars", "whatever", "freedom", "computer",
}

SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl",
             "zxcvbnm")


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 33
    return size


def entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    return round(len(password) * math.log2(charset_size(password) or 1), 2)


def find_patterns(password: str):
    lowered = password.lower()
    found = []
    if lowered in COMMON:
        found.append("common-password")
    for seq in SEQUENCES:
        for length in range(4, len(seq) + 1):
            for start in range(0, len(seq) - length + 1):
                if seq[start:start + length] in lowered:
                    found.append("sequence")
                    break
            else:
                continue
            break
    if re.search(r"(.)\1{2,}", password):
        found.append("repeated-character")
    if re.search(r"(.{2,4})\1{1,}", password):
        found.append("repeated-block")
    if lowered and lowered == password and len(password) > 0:
        found.append("only-lowercase")
    return sorted(set(found))


def score_password(password: str):
    if not password:
        return 0, 0.0, ["empty password"]
    bits = entropy_bits(password)
    patterns = find_patterns(password)
    score = 0
    if bits >= 40:
        score = 1
    if bits >= 60:
        score = 2
    if bits >= 80:
        score = 3
    if bits >= 100:
        score = 4
    if "common-password" in patterns:
        score = 0
    elif "sequence" in patterns and score > 2:
        score = 2
    elif "repeated-block" in patterns and score > 2:
        score = 2
    feedback = []
    if len(password) < 12:
        feedback.append("use at least 12 characters")
    if "common-password" in patterns:
        feedback.append("this is a well-known password")
    if "sequence" in patterns:
        feedback.append("avoid sequences like abcd or 1234")
    if "repeated-block" in patterns:
        feedback.append("avoid repeated blocks like abcabc")
    if charset_size(password) < 62:
        feedback.append("mix upper case, lower case, digits and symbols")
    if score >= 3:
        feedback.append("good length; store it in a password manager")
    return score, bits, feedback


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline password strength auditor")
    parser.add_argument("--password")
    parser.add_argument("--stdin", action="store_true", help="read the password from stdin")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    elif args.password is not None:
        password = args.password
    else:
        parser.error("use --password or --stdin")

    score, bits, feedback = score_password(password)
    if args.json:
        print(json.dumps({"score": score, "entropy_bits": bits,
                          "patterns": find_patterns(password),
                          "feedback": feedback}, indent=2))
    else:
        print(f"score: {score}/4")
        print(f"entropy: {bits} bits")
        for line in feedback:
            print(f"- {line}")
    return 0 if score >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
