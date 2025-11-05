#!/usr/bin/env python3
"""Safe MAC address changer (Linux).

Features:
- Lists interfaces and current MACs
- Validates interface and MAC address formats
- Dry-run by default; require --apply to actually change the MAC
- Saves a backup of the original MAC before applying
- Uses subprocess without shell=True to avoid command injection
- Logs actions to a file

Notes:
- Must be run as root to apply changes. Dry-run and list work as an unprivileged user.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import subprocess
import sys
from pathlib import Path

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")


def log(msg: str) -> None:
	try:
		if os.geteuid() == 0:
			log_path = Path("/var/log/mac_changer.log")
		else:
			log_path = Path.home() / ".local" / "share" / "mac_changer.log"
		log_path.parent.mkdir(parents=True, exist_ok=True)
		with open(log_path, "a", encoding="utf-8") as f:
			f.write(f"{datetime.datetime.utcnow().isoformat()}Z {msg}\n")
	except Exception:
		# Logging must not break the main flow
		pass


def list_interfaces() -> dict:
	"""Return a dict of interface -> mac (string) for available interfaces."""
	net_path = Path("/sys/class/net")
	out = {}
	if not net_path.exists():
		return out
	for iface in net_path.iterdir():
		try:
			mac_file = iface / "address"
			if mac_file.exists():
				mac = mac_file.read_text().strip()
			else:
				mac = ""
			out[iface.name] = mac
		except Exception:
			out[iface.name] = ""
	return out


def get_current_mac(iface: str) -> str:
	path = Path(f"/sys/class/net/{iface}/address")
	if not path.exists():
		raise FileNotFoundError(f"Interface {iface} not found")
	return path.read_text().strip()


def validate_iface(iface: str) -> None:
	if not IFACE_RE.match(iface):
		raise ValueError("Invalid interface name")
	if not Path(f"/sys/class/net/{iface}").exists():
		raise FileNotFoundError("Interface does not exist")
	if iface == "lo":
		raise ValueError("Refusing to operate on loopback interface")


def validate_mac(mac: str) -> None:
	if not MAC_RE.match(mac):
		raise ValueError("Invalid MAC address format")


def backup_original_mac(iface: str, mac: str) -> Path:
	if os.geteuid() == 0:
		base = Path("/var/lib/mac_changer/backups")
	else:
		base = Path.home() / ".local" / "share" / "mac_changer" / "backups"
	base.mkdir(parents=True, exist_ok=True)
	ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
	p = base / f"{iface}-{ts}.orig"
	p.write_text(mac + "\n")
	return p


def run_ip_command(args: list[str]) -> subprocess.CompletedProcess:
	# Always call low-level list args, never shell=True
	return subprocess.run(["ip"] + args, check=False, text=True, capture_output=True)


def apply_mac_change(iface: str, new_mac: str) -> tuple[bool, str]:
	# Bring interface down, change MAC, bring up
	for cmd in (
		["link", "set", "dev", iface, "down"],
		["link", "set", "dev", iface, "address", new_mac],
		["link", "set", "dev", iface, "up"],
	):
		proc = run_ip_command(cmd)
		if proc.returncode != 0:
			return False, f"Command failed: ip {' '.join(cmd)}: {proc.stderr.strip()}"
	# verify
	try:
		cur = get_current_mac(iface)
		if cur.lower() == new_mac.lower():
			return True, "MAC changed successfully"
		return False, "MAC change did not take effect"
	except Exception as e:
		return False, f"Verification failed: {e}"


def generate_random_mac() -> str:
	import random

	# Locally administered, unicast (set the second least-significant bit of the first octet)
	first = random.randint(0x00, 0xFF) & 0xFE | 0x02
	parts = [first] + [random.randint(0x00, 0xFF) for _ in range(5)]
	return ":".join(f"{p:02x}" for p in parts)


def main(argv: list[str] | None = None) -> int:
	parser = argparse.ArgumentParser(description="Safe MAC address changer (dry-run by default)")
	sub = parser.add_subparsers(dest="cmd")

	sub_list = sub.add_parser("list", help="List interfaces and current MAC addresses")

	change = sub.add_parser("change", help="Change MAC address for an interface")
	change.add_argument("iface", help="Interface name")
	change.add_argument("mac", nargs="?", help="New MAC address (or use --random)")
	change.add_argument("--random", action="store_true", help="Generate a random MAC")
	change.add_argument("--apply", action="store_true", help="Actually apply the change (requires root)")

	args = parser.parse_args(argv)

	if args.cmd is None:
		parser.print_help()
		return 2

	if args.cmd == "list":
		data = list_interfaces()
		for k in sorted(data):
			print(f"{k}\t{data[k]}")
		return 0

	if args.cmd == "change":
		iface = args.iface
		try:
			validate_iface(iface)
		except Exception as e:
			print(f"Error: {e}")
			return 3

		if args.random:
			new_mac = generate_random_mac()
		elif args.mac:
			new_mac = args.mac.strip()
		else:
			# interactive prompt (safe input)
			inp = input("Enter new MAC address (or type 'random'): ").strip()
			if inp.lower() == "random":
				new_mac = generate_random_mac()
			else:
				new_mac = inp

		try:
			validate_mac(new_mac)
		except Exception as e:
			print(f"Error: {e}")
			return 4

		try:
			current = get_current_mac(iface)
		except Exception as e:
			print(f"Error reading current MAC: {e}")
			return 5

		print(f"Interface: {iface}")
		print(f"Current MAC: {current}")
		print(f"New MAC: {new_mac}")

		if not args.apply:
			print("Dry-run mode (no changes). Re-run with --apply to apply the change.")
			log(f"DRY-RUN requested: iface={iface} from={current} to={new_mac}")
			return 0

		if os.geteuid() != 0:
			print("Error: applying changes requires root privileges (use sudo).")
			return 6

		# Backup
		try:
			backup_path = backup_original_mac(iface, current)
			log(f"Backup saved: {backup_path}")
		except Exception as e:
			print(f"Warning: failed to save backup: {e}")
			log(f"Backup failed for {iface}: {e}")

		success, msg = apply_mac_change(iface, new_mac)
		print(msg)
		log(f"APPLY result: iface={iface} to={new_mac} success={success} msg={msg}")
		return 0 if success else 7

	return 2


if __name__ == "__main__":
	raise SystemExit(main())