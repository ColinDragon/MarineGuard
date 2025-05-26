# Made by Colin Mckay
# May 26, 2025
# This Python script analyzes the strength of a user-provided password by calculating its entropy, checking for common weaknesses like repeated or sequential characters, and detecting dictionary words or common passwords. It then provides feedback and tips to help improve password security with a colorful animated interface.

import time
import random
import math
import re

# ANSI escape codes for colors and styles
RESET = "\033[0m"
AQUA = "\033[1;36m"
BLUE = "\033[94m"
BOLD = "\033[1m"

# Character sets without ambiguous characters (for entropy calculation)
LOWER = "abcdefghjkmnpqrstuvwxyz"  # removed l and i
UPPER = "ABCDEFGHJKMNPQRSTUVWXYZ"  # removed I and O
DIGITS = "23456789"                # removed 0 and 1
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

# Common passwords (minimal set, can be expanded)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345", "12345678", "qwerty",
    "abc123", "football", "monkey", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "master", "sunshine", "ashley", "bailey",
    "pass123!", "mypassword", "thisismypassword"
}

# Dictionary words to detect inside passwords (minimal example)
DICTIONARY = {
    "password", "letmein", "welcome", "admin", "user", "test", "pass",
    "mypassword", "football", "monkey", "dragon", "sunshine", "baseball", "iloveyou"
}


def bubble_animation(lines=7, width=40):
    """Display a simple ocean bubble animation."""
    bubbles = ['o', 'O', '°']
    print("\n")
    for _ in range(lines):
        line = [' '] * width
        for _ in range(random.randint(1, 4)):
            bubble = random.choice(bubbles)
            pos = random.randint(0, width - 1)
            line[pos] = bubble
        print(BLUE + ''.join(line) + RESET)
        time.sleep(0.1)


def calculate_entropy(password):
    """
    Estimate the entropy of a password based on character pools it uses.
    Higher entropy means a stronger password.
    """
    pool = 0
    if any(c in LOWER for c in password):
        pool += len(LOWER)
    if any(c in UPPER for c in password):
        pool += len(UPPER)
    if any(c in DIGITS for c in password):
        pool += len(DIGITS)
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)

    if pool == 0:
        return 0.0
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def is_common_password(password):
    """Check if the password is a known common password."""
    return password.lower() in COMMON_PASSWORDS


def contains_dictionary_word(password):
    """
    Check if password contains any dictionary word.
    Returns (True, word) if found, else (False, None).
    """
    lower_pw = password.lower()
    for word in DICTIONARY:
        if word in lower_pw:
            return True, word
    return False, None


def has_repeated_chars(password):
    """Detect if 3 or more identical characters appear consecutively."""
    count = 1
    last_char = ''
    for c in password:
        if c == last_char:
            count += 1
            if count >= 3:
                return True
        else:
            count = 1
            last_char = c
    return False


def has_sequential_chars(password):
    """
    Detect 3+ sequential ascending or descending characters,
    like abc, cba, 123, or 321.
    """
    if len(password) < 3:
        return False
    codes = [ord(c.lower()) for c in password]
    for i in range(len(codes) - 2):
        if codes[i] + 1 == codes[i + 1] and codes[i] + 2 == codes[i + 2]:
            return True
        if codes[i] - 1 == codes[i + 1] and codes[i] - 2 == codes[i + 2]:
            return True
    return False


def explain_weakness(password):
    """
    Generate a list of reasons why the password is considered weak.
    """
    reasons = []
    if len(password) < 8:
        reasons.append("Too short (less than 8 characters)")
    if not any(c in UPPER for c in password):
        reasons.append("Missing uppercase letters")
    if not any(c in LOWER for c in password):
        reasons.append("Missing lowercase letters")
    if not any(c in DIGITS for c in password):
        reasons.append("Missing digits")
    if not any(c in SYMBOLS for c in password):
        reasons.append("Missing special characters")
    if len(set(password)) < 5:
        reasons.append("Low character variety")
    if has_repeated_chars(password):
        reasons.append("Contains repeated characters (3 or more in a row)")
    if has_sequential_chars(password):
        reasons.append("Contains sequential characters (e.g., abc, 123)")
    return reasons


def analyze_password(password):
    """
    Main analysis function to check password strength, entropy,
    commonality, dictionary words, and weaknesses.
    """
    bubble_animation()
    print(AQUA + BOLD + "🌊 Oceanic Password Analyzer 🌊" + RESET)
    print(f"\nAnalyzing password: {BOLD}{password}{RESET}")

    # Check for common password list
    if is_common_password(password):
        print("\n❌ Password is found in the list of common passwords. Very weak!")
        print("💡 Avoid using common passwords that are easy to guess or found in leaks.")
        return

    # Check dictionary words inside password
    contains_word, word = contains_dictionary_word(password)
    if contains_word:
        print(f"\n❌ Password contains common dictionary word: '{word}'")
        print("💡 Try mixing unrelated words or adding symbols/numbers to increase strength.")

    # Calculate entropy
    entropy = calculate_entropy(password)
    print(f"\n🔐 Entropy Score: {BOLD}{entropy} bits{RESET}")

    # Determine strength based on entropy and weaknesses
    weaknesses = explain_weakness(password)
    if entropy < 28 or weaknesses:
        strength = "Very Weak" if entropy < 28 else "Weak"
    elif entropy < 60:
        strength = "Moderate"
    else:
        strength = "Strong"

    print(f"\n💪 Strength: {AQUA}{strength}{RESET}")

    # Print weaknesses and tips if password is weak
    if strength in ["Very Weak", "Weak"]:
        print("\n❌ Weaknesses Found:")
        for reason in weaknesses:
            print(f" - {reason}")
        print("\n💡 Tips to Improve:")
        print(" - Use at least 12 characters")
        print(" - Mix uppercase, lowercase, digits, and symbols")
        print(" - Avoid common words, patterns, repeated characters, and sequences")
    elif strength == "Moderate":
        print("\n✅ This password is moderately strong but can be improved.")
    else:
        print("\n✅ This is a strong password. Well done!")


def main():
    """Run the password analyzer in a loop until the user quits."""
    while True:
        password = input("\nEnter a password to analyze (or 'quit' to exit): ").strip()
        if password.lower() == 'quit':
            print("Exiting password analyzer.")
            break
        if not password:
            print("Please enter a non-empty password.")
            continue
        analyze_password(password)


if __name__ == "__main__":
    main()
