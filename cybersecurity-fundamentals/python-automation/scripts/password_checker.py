#!/usr/bin/env python3
"""Score password strength and suggest improvements.

By default it scores a built-in list of example passwords and prints a
report, so it runs without any input. Add --interactive to type your own
(input is hidden), or --file to score a list, one password per line.

Usage:
    python3 password_checker.py
    python3 password_checker.py --interactive
    python3 password_checker.py --file candidates.txt

This is a teaching tool, not a real strength meter: length matters far more
than character classes, and real checkers compare against breach lists.
"""

import argparse
import getpass
import string
import sys

MAX_SCORE = 11
COMMON = {"password", "123456", "12345678", "qwerty", "admin", "letmein", "welcome", "iloveyou"}
EXAMPLES = [
    "123456", "password", "Password1", "MyP@ssw0rd", "SuperSecure123!",
    "admin", "P@ssw0rd2024!", "weakpass", "StrongP@ssw0rd123!",
]

CLASSES = [
    ("uppercase letters (A-Z)", lambda c: c.isupper()),
    ("lowercase letters (a-z)", lambda c: c.islower()),
    ("digits (0-9)", lambda c: c.isdigit()),
    ("symbols such as ! @ # $ %", lambda c: c in string.punctuation),
]


def score_password(pw):
    """Return (score 0..MAX_SCORE, list of suggestions)."""
    score, tips = 0, []
    if len(pw) >= 8:
        score += 2
    else:
        tips.append("Use at least 8 characters")
    if len(pw) >= 12:
        score += 1
    else:
        tips.append("12 or more characters is better")

    for label, test in CLASSES:
        if any(test(c) for c in pw):
            score += 2
        else:
            tips.append(f"Add {label}")

    if pw.lower() in COMMON:
        score -= 5
        tips.append("This is one of the most common passwords; never use it")
    # Few distinct characters in a short password, or the same character 3+ times
    # in a row. Long passphrases naturally repeat letters, so the ratio test
    # only applies below 16 characters.
    low_variety = len(pw) < 16 and len(set(pw)) < len(pw) * 0.6
    has_run = any(pw[i] == pw[i + 1] == pw[i + 2] for i in range(len(pw) - 2))
    if low_variety or has_run:
        score -= 2
        tips.append("Too many repeated characters")
    return max(0, score), tips


def rating(score):
    for threshold, label in ((9, "VERY STRONG"), (7, "STRONG"), (5, "MODERATE"), (3, "WEAK")):
        if score >= threshold:
            return label
    return "VERY WEAK"


def print_result(label, pw):
    score, tips = score_password(pw)
    print(f"{label:<22} {score:>2}/{MAX_SCORE}  {rating(score)}")
    for t in tips:
        print(f"{'':<26}- {t}")
    return score


def report(passwords):
    scores = []
    for pw in passwords:
        scores.append((print_result(pw, pw), pw))
    counts = {}
    for s, _ in scores:
        counts[rating(s)] = counts.get(rating(s), 0) + 1
    print("\n=== Report ===")
    print(f"Tested: {len(scores)}")
    for label in ("VERY STRONG", "STRONG", "MODERATE", "WEAK", "VERY WEAK"):
        if label in counts:
            print(f"  {label:<12} {counts[label]} ({counts[label] / len(scores):.0%})")
    best = max(scores, key=lambda t: t[0])
    worst = min(scores, key=lambda t: t[0])
    print(f"Best:  {best[1]!r} ({best[0]})   Worst: {worst[1]!r} ({worst[0]})")
    print(f"Average score: {sum(s for s, _ in scores) / len(scores):.1f}/{MAX_SCORE}")


def interactive():
    print("Type a password to score it (it will not be shown). Empty line or Ctrl+D to quit.")
    while True:
        try:
            pw = getpass.getpass("password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not pw:
            break
        print_result("your password", pw)


def main():
    parser = argparse.ArgumentParser(description="Score password strength.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--interactive", action="store_true", help="type passwords to check (hidden input)")
    group.add_argument("--file", help="score each line of this file")
    args = parser.parse_args()

    if args.interactive:
        interactive()
        return 0
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                passwords = [line.rstrip("\n") for line in f if line.strip()]
        except OSError as e:
            print(f"Error reading {args.file}: {e}", file=sys.stderr)
            return 1
        if not passwords:
            print("No passwords in file.", file=sys.stderr)
            return 1
    else:
        passwords = EXAMPLES
    report(passwords)
    return 0


if __name__ == "__main__":
    sys.exit(main())
