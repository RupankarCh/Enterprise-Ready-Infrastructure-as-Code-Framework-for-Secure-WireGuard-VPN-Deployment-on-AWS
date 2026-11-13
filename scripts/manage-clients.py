#!/usr/bin/env python3

"""
CloudVPN client key management.

Generates WireGuard client key pairs locally.
Private keys are never transferred to the VPN server.
"""

import errno
import tempfile
import yaml
import base64
import binascii
import ipaddress
import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
import fcntl
from functools import wraps


CLIENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def validate_client_name(name):
    if not CLIENT_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "Client name must contain 1-32 letters, numbers, "
            "underscores or hyphens and start with a letter or number."
        )


def ensure_wg_available():
    try:
        result = subprocess.run(
            ["wg", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise RuntimeError("WireGuard 'wg' utility is required.")

    return result.stdout.strip() or result.stderr.strip()


def create_restricted_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(
            f"Directory must not be a symbolic link: {path}"
        ) from exc

    try:
        metadata = os.fstat(fd)

        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"Not a directory: {path}")

        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def create_exclusive_file(path, content, mode):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags, mode)

    try:
        os.fchmod(fd, mode)

        with os.fdopen(fd, "w", encoding="ascii") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def generate_key_pair(name, output_directory):
    validate_client_name(name)
    ensure_wg_available()

    private_directory = output_directory / "private"
    public_directory = output_directory / "public"

    create_restricted_directory(output_directory)
    create_restricted_directory(private_directory)
    create_restricted_directory(public_directory)

    private_path = private_directory / f"{name}.key"
    public_path = public_directory / f"{name}.pub"

    if private_path.exists() or public_path.exists():
        raise FileExistsError(
            f"Key files already exist for '{name}'. "
            "Existing keys will not be overwritten."
        )

    private_key = subprocess.run(
        ["wg", "genkey"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    public_key = subprocess.run(
        ["wg", "pubkey"],
        input=private_key + "\n",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if not private_key or not public_key:
        raise RuntimeError("WireGuard returned an empty key.")

    created_files = []

    try:
        create_exclusive_file(private_path, private_key + "\n", 0o600)
        created_files.append(private_path)

        create_exclusive_file(public_path, public_key + "\n", 0o644)
        created_files.append(public_path)

    except Exception:
        for path in created_files:
            try:
                path.unlink()
            except OSError:
                pass
        raise

    print(f"Client '{name}' key pair generated successfully.")
    print(f"Private key file: {private_path}")
    print(f"Public key file:  {public_path}")
    print("Private key contents were not displayed.")

    return public_path

def read_private_key(path):
    flags = os.O_RDONLY

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)

    with os.fdopen(fd, "r", encoding="ascii") as handle:
        metadata = os.fstat(handle.fileno())

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Private key must be a regular file.")

        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PermissionError(
                "Registry must not allow group or other write access."
            )

        key = handle.read().strip()

    if not key:
        raise ValueError("Client private key is empty.")

    return key


def validate_public_key(key):
    try:
        decoded = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid server public key encoding.")

    if len(decoded) != 32:
        raise ValueError("Server public key must decode to 32 bytes.")

    return key


def validate_endpoint(endpoint):
    if not endpoint or any(c.isspace() for c in endpoint):
        raise ValueError("Invalid VPN endpoint.")

    if endpoint.startswith("["):
        closing = endpoint.find("]")

        if closing == -1 or endpoint[closing + 1:closing + 2] != ":":
            raise ValueError("IPv6 endpoints must use [address]:port.")

        host = endpoint[1:closing]
        port = endpoint[closing + 2:]

        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError("Invalid IPv6 endpoint address.")

    else:
        if endpoint.count(":") != 1:
            raise ValueError("Endpoint must use hostname:port or IPv4:port.")

        host, port = endpoint.rsplit(":", 1)

        if not host:
            raise ValueError("Endpoint hostname cannot be empty.")

        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            if len(host) > 253:
                raise ValueError("Invalid endpoint hostname.")

            if host.endswith(".."):
                raise ValueError("Invalid endpoint hostname.")

            labels = host[:-1].split(".") if host.endswith(".") else host.split(".")

            if not all(
                re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                    label,
                )
                for label in labels
            ):
                raise ValueError("Invalid endpoint hostname.")

    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Endpoint port must be between 1 and 65535.")


def generate_profile(
    name,
    address,
    dns,
    server_public_key_file,
    endpoint,
    allowed_ips,
    keepalive,
    output_directory,
):
    validate_client_name(name)
    validate_endpoint(endpoint)

    address = str(ipaddress.ip_interface(address))

    dns_addresses = [str(ipaddress.ip_address(item.strip()))
                     for item in dns.split(",")]

    if not dns_addresses:
        raise ValueError("At least one DNS address is required.")

    allowed_networks = [
        str(ipaddress.ip_network(item.strip(), strict=False))
        for item in allowed_ips.split(",")
    ]

    if not allowed_networks:
        raise ValueError("At least one AllowedIPs network is required.")

    if not 0 <= keepalive <= 65535:
        raise ValueError("Keepalive must be between 0 and 65535.")

    private_path = output_directory / "private" / f"{name}.key"
    public_path = server_public_key_file

    private_key = read_private_key(private_path)
    server_public_key = validate_public_key(
        public_path.read_text(encoding="ascii").strip()
    )

    derived_public_key = subprocess.run(
        ["wg", "pubkey"],
        input=private_key + "\n",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if not derived_public_key:
        raise RuntimeError("Could not verify client private key.")

    profile = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {address}\n"
        f"DNS = {', '.join(dns_addresses)}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {', '.join(allowed_networks)}\n"
        f"PersistentKeepalive = {keepalive}\n"
    )

    profile_directory = output_directory / "profiles"
    create_restricted_directory(profile_directory)

    profile_path = profile_directory / f"{name}.conf"

    create_exclusive_file(profile_path, profile, 0o600)

    print(f"Profile generated for '{name}'.")
    print(f"Profile location: {profile_path}")
    print("Private key contents were not displayed.")

def open_registry_file(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                "Registry cannot be a symbolic link."
            ) from exc
        raise

    try:
        metadata = os.fstat(fd)

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Registry must be a regular file.")

        if metadata.st_uid != os.geteuid():
            raise PermissionError(
                "Registry must be owned by the current user."
            )

        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PermissionError(
                "Registry must not allow group or other access."
            )

        return fd

    except Exception:
        os.close(fd)
        raise

def registry_locked(registry_arg_index):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            registry_value = kwargs.get("registry_file")

            if registry_value is None:
                if len(args) <= registry_arg_index:
                    raise TypeError("Registry path is required.")
                registry_value = args[registry_arg_index]

            registry_path = Path(registry_value)
            registry_path.parent.mkdir(parents=True, exist_ok=True)

            lock_path = Path(str(registry_path) + ".lock")

            if not hasattr(os, "O_NOFOLLOW"):
                raise RuntimeError("O_NOFOLLOW support is required.")

            flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW

            try:
                fd = os.open(lock_path, flags, 0o600)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError(
                        "Registry lock cannot be a symbolic link."
                    ) from exc
                raise

            try:
                metadata = os.fstat(fd)

                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("Registry lock must be a regular file.")

                if metadata.st_uid != os.geteuid():
                    raise PermissionError(
                        "Registry lock must be owned by the current user."
                    )

                if metadata.st_nlink != 1:
                    raise ValueError(
                        "Registry lock must not have additional hard links."
                    )

                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)

                return function(*args, **kwargs)

            finally:
                os.close(fd)

        return wrapper
    return decorator

@registry_locked(5)
def register_client(
    name,
    address,
    network,
    server_address,
    public_key_file,
    registry_file,
):
    validate_client_name(name)

    vpn_network = ipaddress.ip_network(network, strict=True)
    server_ip = ipaddress.ip_interface(server_address).ip
    client_interface = ipaddress.ip_interface(address)

    if client_interface.version != vpn_network.version:
        raise ValueError("Client address IP version differs from VPN subnet.")

    if client_interface.network.prefixlen != vpn_network.max_prefixlen:
        raise ValueError("Client address must use a host prefix.")

    client_ip = client_interface.ip

    if client_ip not in vpn_network:
        raise ValueError("Client address is outside the VPN subnet.")

    if client_ip == server_ip:
        raise ValueError("Client cannot use the server VPN address.")

    if isinstance(vpn_network, ipaddress.IPv4Network):
        if client_ip in (vpn_network.network_address,
                         vpn_network.broadcast_address):
            raise ValueError("Client cannot use network or broadcast address.")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(public_key_file, flags)

    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        metadata = os.fstat(handle.fileno())

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Public key must be a regular file.")

        public_key = validate_public_key(handle.read().strip())

    registry_file = Path(registry_file)
    registry_directory = registry_file.parent

    registry_directory.mkdir(parents=True, exist_ok=True)

    if not registry_directory.is_dir():
        raise ValueError("Registry parent must be a directory.")

    if registry_file.is_symlink():
        raise ValueError("Registry cannot be a symbolic link.")

    if registry_file.exists():
        if not registry_file.is_file():
            raise ValueError("Registry must be a regular file.")

        fd = open_registry_file(registry_file)

        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            registry = yaml.safe_load(handle) or {}

        if not isinstance(registry, dict):
            raise ValueError("Registry must contain a YAML mapping.")
    else:
        registry = {}

    clients = registry.setdefault("wireguard_clients", [])

    if not isinstance(clients, list):
        raise ValueError("wireguard_clients must be a YAML list.")

    for existing in clients:
        if not isinstance(existing, dict):
            raise ValueError("Existing registry entry is invalid.")

        if existing.get("name") == name:
            raise ValueError("Client name is already registered.")

        if existing.get("address") == str(client_interface):
            raise ValueError("Client IP address is already registered.")

        if existing.get("public_key") == public_key:
            raise ValueError("Public key is already registered.")

    clients.append({
        "name": name,
        "address": str(client_interface),
        "public_key": public_key,
    })

    content = yaml.safe_dump(
        registry,
        sort_keys=False,
        default_flow_style=False,
    )

    temporary_path = None

    try:
        fd, temporary_path = tempfile.mkstemp(
            prefix=".clients-",
            suffix=".tmp",
            dir=registry_directory,
        )

        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, registry_file)
        temporary_path = None

    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    print(f"Client '{name}' registered successfully.")
    print(f"Registry: {registry_file}")
    print(f"VPN address: {client_interface}")
    print("Only the public key was registered.")

def list_clients(registry_file):
    registry_file = Path(registry_file)

    try:
        fd = open_registry_file(registry_file)
    except FileNotFoundError:
        print("No client registry found.")
        return

    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        registry = yaml.safe_load(handle) or {}

    if not isinstance(registry, dict):
        raise ValueError("Registry must contain a YAML mapping.")

    clients = registry.get("wireguard_clients", [])

    if not isinstance(clients, list):
        raise ValueError("wireguard_clients must be a YAML list.")

    if not clients:
        print("No clients registered.")
        return

    print(f"\nRegistered WireGuard clients: {len(clients)}")
    print("-" * 55)

    for client in clients:
        if not isinstance(client, dict):
            raise ValueError("Invalid client entry in registry.")

        name = client.get("name", "Unknown")
        address = client.get("address", "Unknown")

        print(f"Name:    {name}")
        print(f"Address: {address}")
        print("-" * 55)

@registry_locked(1)
def revoke_client(name, registry_file):
    validate_client_name(name)

    registry_file = Path(registry_file)

    if registry_file.is_symlink():
        raise ValueError("Registry cannot be a symbolic link.")

    if not registry_file.exists():
        raise ValueError("Client registry does not exist.")

    try:
        fd = open_registry_file(registry_file)
    except FileNotFoundError:
        print("No client registry found.")
        return

    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        registry = yaml.safe_load(handle) or {}

    if not isinstance(registry, dict):
        raise ValueError("Registry must contain a YAML mapping.")

    clients = registry.get("wireguard_clients", [])

    if not isinstance(clients, list):
        raise ValueError("wireguard_clients must be a YAML list.")

    matches = [
        client for client in clients
        if isinstance(client, dict) and client.get("name") == name
    ]

    if not matches:
        raise ValueError(f"Client '{name}' is not registered.")

    if len(matches) > 1:
        raise ValueError("Duplicate client entries found; refusing revocation.")

    registry["wireguard_clients"] = [
        client for client in clients
        if not isinstance(client, dict) or client.get("name") != name
    ]

    content = yaml.safe_dump(
        registry,
        sort_keys=False,
        default_flow_style=False,
    )

    temporary_path = None

    try:
        fd, temporary_path = tempfile.mkstemp(
            prefix=".clients-",
            suffix=".tmp",
            dir=registry_file.parent,
        )

        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, registry_file)
        temporary_path = None

    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    print(f"Client '{name}' revoked from the local registry.")
    print("Local private keys and client profiles were preserved.")
    print("The running VPN server has not been modified.")

def main():
    parser = argparse.ArgumentParser(
        description="Secure local WireGuard client management."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a client key pair.",
    )

    generate_parser.add_argument("name", help="Client name.")

    generate_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("clients"),
        help="Local output directory (default: ./clients).",
    )

    profile_parser = subparsers.add_parser(
        "profile",
        help="Generate a client WireGuard profile.",
    )

    profile_parser.add_argument("name")
    profile_parser.add_argument("--address", required=True)
    profile_parser.add_argument("--dns", default="1.1.1.1")
    profile_parser.add_argument("--server-public-key-file", type=Path, required=True)
    profile_parser.add_argument("--endpoint", required=True)
    profile_parser.add_argument(
        "--allowed-ips",
        default="0.0.0.0/0, ::/0",
    )
    profile_parser.add_argument("--keepalive", type=int, default=25)
    profile_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("clients"),
    )

    register_parser = subparsers.add_parser(
        "register",
        help="Register a client in the Ansible peer registry.",
    )

    register_parser.add_argument("name", help="Client name.")
    register_parser.add_argument("--address", required=True)
    register_parser.add_argument(
        "--network",
        default="10.8.0.0/24",
    )
    register_parser.add_argument(
        "--server-address",
        default="10.8.0.1/24",
    )
    register_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("clients"),
    )
    register_parser.add_argument(
        "--registry-file",
        type=Path,
        default=Path("ansible/vars/clients.yml"),
    )

    list_parser = subparsers.add_parser(
        "list",
        help="List registered WireGuard clients.",
    )

    list_parser.add_argument(
        "--registry-file",
        type=Path,
        default=Path("ansible/vars/clients.yml"),
    )

    revoke_parser = subparsers.add_parser(
        "revoke",
        help="Revoke a client from the local Ansible registry.",
    )

    revoke_parser.add_argument("name", help="Client name to revoke.")

    revoke_parser.add_argument(
        "--registry-file",
        type=Path,
        default=Path("ansible/vars/clients.yml"),
    )

    args = parser.parse_args()

    try:
        if args.command == "generate":
            generate_key_pair(args.name, args.output_dir)

        elif args.command == "profile":
            generate_profile(
                name=args.name,
                address=args.address,
                dns=args.dns,
                server_public_key_file=args.server_public_key_file,
                endpoint=args.endpoint,
                allowed_ips=args.allowed_ips,
                keepalive=args.keepalive,
                output_directory=args.output_dir,
            )

        elif args.command == "revoke":
            revoke_client(
                name=args.name,
                registry_file=args.registry_file,
            )

        elif args.command == "register":
            register_client(
                name=args.name,
                address=args.address,
                network=args.network,
                server_address=args.server_address,
                public_key_file=(
                    args.output_dir / "public" / f"{args.name}.pub"
                ),
                registry_file=args.registry_file,
            )

        elif args.command == "list":
            list_clients(args.registry_file)

    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
