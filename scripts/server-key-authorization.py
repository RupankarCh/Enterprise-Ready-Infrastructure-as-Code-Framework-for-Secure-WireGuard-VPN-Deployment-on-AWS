#!/usr/bin/env python3

import argparse
import fcntl
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


INSTANCE_PATTERN = re.compile(r"^i-[0-9a-f]{8,17}$")


@contextmanager
def authorization_lock(marker_path):
    marker_path = Path(marker_path)
    lock_path = marker_path.with_name(marker_path.name + ".lock")

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(lock_path, flags, 0o600)

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Authorization lock must be a regular file")

        if info.st_mode & 0o077:
            raise ValueError("Authorization lock permissions must be 0600")

        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)



def validate_instance_id(value):
    if not INSTANCE_PATTERN.fullmatch(value):
        raise ValueError("Invalid EC2 instance ID")
    return value


def read_marker(path):
    path = Path(path)

    if path.is_symlink():
        raise ValueError("Authorization marker cannot be a symlink")

    if not path.exists():
        return None

    info = path.lstat()

    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Authorization marker must be a regular file")

    if info.st_mode & 0o077:
        raise ValueError("Authorization marker permissions must be 0600")

    value = path.read_text(encoding="utf-8").strip()

    if value == "PENDING":
        return value

    if INSTANCE_PATTERN.fullmatch(value):
        return value

    raise ValueError("Invalid authorization marker")


def write_marker(path, value):
    path = Path(path)

    if path.is_symlink():
        raise ValueError("Authorization marker cannot be a symlink")

    fd, temporary = tempfile.mkstemp(
        prefix=".cloudvpn-key-auth-",
        dir=path.parent,
    )

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(path):
    with authorization_lock(path):
        current = read_marker(path)

        if current == "PENDING":
            return

        if current is not None:
            raise ValueError(
                "Authorization already bound to an instance; "
                "refusing overwrite"
            )

        write_marker(path, "PENDING")


def bind(path, instance_id):
    instance_id = validate_instance_id(instance_id)

    with authorization_lock(path):
        current = read_marker(path)

        if current == instance_id:
            return

        if current != "PENDING":
            raise ValueError("No pending authorization exists")

        write_marker(path, instance_id)


def check(path, instance_id):
    instance_id = validate_instance_id(instance_id)

    with authorization_lock(path):
        return read_marker(path) == instance_id


def consume(path, instance_id):
    instance_id = validate_instance_id(instance_id)

    with authorization_lock(path):
        current = read_marker(path)

        if current != instance_id:
            raise ValueError(
                "Authorization does not match this instance"
            )

        Path(path).unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=["prepare", "bind", "check", "consume"],
    )
    parser.add_argument("--marker", required=True)
    parser.add_argument("--instance-id")

    args = parser.parse_args()

    try:
        if args.action == "prepare":
            prepare(args.marker)
            print("Authorization prepared.")

        elif args.action == "bind":
            if not args.instance_id:
                raise ValueError("Instance ID is required")
            bind(args.marker, args.instance_id)
            print("Authorization bound to instance.")

        elif args.action == "check":
            if not args.instance_id:
                raise ValueError("Instance ID is required")
            print("true" if check(args.marker, args.instance_id) else "false")

        elif args.action == "consume":
            if not args.instance_id:
                raise ValueError("Instance ID is required")
            consume(args.marker, args.instance_id)
            print("Authorization consumed.")

        return 0

    except (OSError, ValueError) as exc:
        print(f"Authorization error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
