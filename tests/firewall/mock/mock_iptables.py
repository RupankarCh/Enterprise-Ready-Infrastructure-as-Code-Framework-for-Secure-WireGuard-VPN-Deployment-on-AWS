#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path

STATE_FILE = Path(os.environ.get("MOCK_IPTABLES_STATE", "/tmp/mock-iptables.json"))
LOG_FILE = Path(os.environ.get("MOCK_IPTABLES_LOG", "/tmp/mock-iptables.log"))

BUILTIN_CHAINS = {
    "INPUT": [],
    "FORWARD": [],
    "OUTPUT": [],
}


def load_state():
    if not STATE_FILE.exists():
        return {
            "chains": BUILTIN_CHAINS.copy(),
            "policies": {
                "INPUT": "ACCEPT",
                "FORWARD": "ACCEPT",
                "OUTPUT": "ACCEPT",
            },
        }

    return json.loads(STATE_FILE.read_text())


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def log(message):
    with LOG_FILE.open("a") as handle:
        handle.write(message + "\n")


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def inject_failure(stage, command):
    configured_command = os.environ.get("MOCK_IPTABLES_FAIL_ON")
    configured_stage = os.environ.get("MOCK_IPTABLES_FAIL_STAGE", "before")

    if configured_command == command and configured_stage == stage:
        fail(f"MOCK FAILURE ({stage}): {command}")

    configured_failures = os.environ.get("MOCK_IPTABLES_FAILURES", "")

    for entry in configured_failures.splitlines():
        if "|" not in entry:
            continue

        failure_stage, failure_command = entry.split("|", 1)

        if failure_stage == stage and failure_command == command:
            fail(f"MOCK FAILURE ({stage}): {command}")


def finish_state(state, command):
    save_state(state)
    inject_failure("after", command)


def main():
    args = sys.argv[1:]
    command = " ".join(args)
    log(command)

    state = load_state()
    chains = state["chains"]

    inject_failure("before", command)

    if not args:
        fail("Missing iptables arguments")

    operation = args[0]

    if operation == "-S":
        inject_failure("inspect", command)

        inspect_after = os.environ.get(
            "MOCK_IPTABLES_FAIL_INSPECT_AFTER"
        )

        if inspect_after:
            marker = LOG_FILE.with_suffix(".inspect-failure-used")
            history = LOG_FILE.read_text().splitlines()

            if inspect_after in history and not marker.exists():
                marker.write_text("used\\n")
                fail(
                    f"MOCK FAILURE (conditional inspect): "
                    f"{command} after {inspect_after}"
                )

        if len(args) == 1:
            for chain, policy in state["policies"].items():
                print(f"-P {chain} {policy}")

            for chain, rules in chains.items():
                if chain not in state["policies"]:
                    print(f"-N {chain}")
                for rule in rules:
                    print(f"-A {chain} {rule}")
            return

        chain = args[1]

        if chain not in chains:
            fail(f"iptables: Bad rule (does a matching chain exist in that table?)")

        if chain in state["policies"]:
            print(f"-P {chain} {state['policies'][chain]}")
        else:
            print(f"-N {chain}")

        for rule in chains[chain]:
            print(f"-A {chain} {rule}")
        return

    if operation == "-N":
        chain = args[1]

        if chain in chains:
            fail(f"Chain already exists: {chain}")

        chains[chain] = []
        finish_state(state, command)
        return

    if operation == "-A":
        chain = args[1]

        if chain not in chains:
            fail(f"Chain does not exist: {chain}")

        chains[chain].append(" ".join(args[2:]))
        finish_state(state, command)
        return

    if operation == "-I":
        chain = args[1]

        if chain not in chains:
            fail(f"Chain does not exist: {chain}")

        position = int(args[2]) - 1
        rule = " ".join(args[3:])
        chains[chain].insert(position, rule)
        finish_state(state, command)
        return

    if operation == "-D":
        chain = args[1]

        if chain not in chains:
            fail(f"Chain does not exist: {chain}")

        rule = " ".join(args[2:])

        try:
            chains[chain].remove(rule)
        except ValueError:
            fail(f"Rule does not exist in chain: {chain}")

        finish_state(state, command)
        return

    if operation == "-E":
        old_chain = args[1]
        new_chain = args[2]

        if old_chain not in chains:
            fail(f"Chain does not exist: {old_chain}")

        if new_chain in chains:
            fail(f"Target chain already exists: {new_chain}")

        chains[new_chain] = chains.pop(old_chain)
        finish_state(state, command)
        return

    if operation == "-F":
        chain = args[1]

        if chain not in chains:
            fail(f"Chain does not exist: {chain}")

        chains[chain] = []
        finish_state(state, command)
        return

    if operation == "-X":
        chain = args[1]

        if chain not in chains:
            fail(f"Chain does not exist: {chain}")

        if chains[chain]:
            fail(f"Chain is not empty: {chain}")

        for source_chain, rules in chains.items():
            if source_chain == chain:
                continue

            for rule in rules:
                tokens = rule.split()

                for index, token in enumerate(tokens[:-1]):
                    if token in ("-j", "-g") and tokens[index + 1] == chain:
                        fail(
                            f"Chain is referenced by another chain: "
                            f"{source_chain} -> {chain}"
                        )

        del chains[chain]
        finish_state(state, command)
        return

    fail(f"Unsupported mock iptables operation: {command}")


if __name__ == "__main__":
    main()
