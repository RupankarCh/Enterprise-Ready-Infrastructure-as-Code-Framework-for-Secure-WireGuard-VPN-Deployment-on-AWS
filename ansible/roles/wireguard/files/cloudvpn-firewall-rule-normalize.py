#!/usr/bin/env python3

"""
CloudVPN firewall rule normalizer.

Supports:
- iptables -S CHAIN output
- iptables-save output

Normalizes option ordering within individual rules while strictly
preserving firewall rule ordering.
"""

import ipaddress
import shlex
import sys


SUPPORTED_OPTIONS = {
    "-i": 1,
    "-o": 1,
    "-s": 1,
    "-d": 1,
    "-m": 1,
    "--ctstate": 1,
    "-j": 1,
}


class RuleError(Exception):
    pass


def normalize_rule(rule):
    tokens = shlex.split(rule)

    if not tokens:
        raise RuleError("Empty rule encountered")

    clauses = []
    index = 0
    seen_options = set()
    jump_count = 0

    while index < len(tokens):
        negated = False

        if tokens[index] == "!":
            negated = True
            index += 1

            if index >= len(tokens):
                raise RuleError("Negation without an option")

        option = tokens[index]

        if option not in SUPPORTED_OPTIONS:
            raise RuleError(f"Unsupported rule option: {option}")

        if option in seen_options:
            raise RuleError(f"Duplicate rule option: {option}")

        if negated and option != "-s":
            raise RuleError(
                f"Negation is not permitted for option: {option}"
            )

        seen_options.add(option)
        index += 1

        argument_count = SUPPORTED_OPTIONS[option]

        if index + argument_count > len(tokens):
            raise RuleError(f"Missing argument for {option}")

        arguments = tuple(tokens[index:index + argument_count])

        if any(not argument or argument == "!" for argument in arguments):
            raise RuleError(f"Invalid argument for {option}")

        if option in ("-s", "-d"):
            try:
                network = ipaddress.ip_network(
                    arguments[0], strict=False
                )
            except ValueError as exc:
                raise RuleError(
                    f"Invalid IPv4 address or CIDR for {option}: "
                    f"{arguments[0]}"
                ) from exc

            if network.version != 4:
                raise RuleError(
                    f"IPv6 is not supported for {option}: "
                    f"{arguments[0]}"
                )

        if option == "-j":
            jump_count += 1

        clauses.append((option, negated, arguments))
        index += argument_count

    if jump_count != 1:
        raise RuleError(
            f"Expected exactly one jump target; found {jump_count}"
        )

    # Match clauses are normalized; firewall rule sequence is preserved.
    return tuple(sorted(clauses))


def read_actual_rules(chain, input_text):
    rules = []
    declarations = 0

    for line in input_text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("*") or line == "COMMIT":
            continue

        tokens = shlex.split(line)

        if not tokens:
            continue

        # iptables-save chain declaration: :CHAIN POLICY [packets:bytes]
        if tokens[0].startswith(":"):
            declared_chain = tokens[0][1:]

            if declared_chain == chain:
                declarations += 1

            continue

        # iptables -S chain declaration: -N CHAIN
        if tokens[0] == "-N":
            if len(tokens) != 2:
                raise RuleError("Malformed chain declaration")

            if tokens[1] == chain:
                declarations += 1

            continue

        # iptables-save policy declarations.
        if tokens[0] == "-P":
            if len(tokens) != 3:
                raise RuleError("Malformed policy declaration")
            continue

        if tokens[0] == "-A":
            if len(tokens) < 3:
                raise RuleError("Incomplete iptables rule")

            if tokens[1] == chain:
                rules.append(
                    " ".join(
                        shlex.quote(token) for token in tokens[2:]
                    )
                )
            continue

        raise RuleError(f"Unexpected iptables output: {line}")

    if declarations != 1:
        raise RuleError(
            f"Expected exactly one declaration for {chain}; "
            f"found {declarations}"
        )

    return rules


def main():
    if len(sys.argv) < 4:
        print(
            "Usage: normalizer.py exact|prefix CHAIN EXPECTED_RULE...",
            file=sys.stderr,
        )
        return 2

    mode = sys.argv[1]
    chain = sys.argv[2]
    expected_rules = sys.argv[3:]

    if mode not in ("exact", "prefix"):
        print("Invalid verification mode", file=sys.stderr)
        return 2

    try:
        actual_rules = read_actual_rules(
            chain,
            sys.stdin.read(),
        )

        expected = [
            normalize_rule(rule)
            for rule in expected_rules
        ]

        actual = [
            normalize_rule(rule)
            for rule in actual_rules
        ]

        if len(expected) != len(set(expected)):
            raise RuleError("Expected rules contain duplicates")

        if len(actual) != len(set(actual)):
            raise RuleError("Actual chain contains duplicate rules")

        if mode == "exact" and len(actual) != len(expected):
            raise RuleError(
                f"Rule count mismatch: expected {len(expected)}, "
                f"found {len(actual)}"
            )

        if mode == "prefix" and len(actual) > len(expected):
            raise RuleError(
                f"Staging chain contains too many rules: "
                f"expected at most {len(expected)}, found {len(actual)}"
            )

        for index, actual_rule in enumerate(actual):
            if actual_rule != expected[index]:
                raise RuleError(
                    f"Rule mismatch at position {index + 1}"
                )

        return 0

    except (RuleError, ValueError) as exc:
        print(
            f"[CloudVPN Rule Verification ERROR] {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
