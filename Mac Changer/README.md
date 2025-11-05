mac_changer
===========

Safe MAC address changer for Linux.

Features
- List network interfaces and their MAC addresses.
- Dry-run mode by default. Use `--apply` to make changes (requires root).
- Validates interface names and MAC address format to avoid injection.
- Generates locally-administered random MAC addresses.
- Saves backups of original MACs and logs actions.

Quick usage

List interfaces:

```bash
python3 mac_changer.py list
```

Change an interface (dry-run):

```bash
python3 mac_changer.py change eth0 12:34:56:78:9a:bc
```

Apply the change (must be root):

```bash
sudo python3 mac_changer.py change eth0 12:34:56:78:9a:bc --apply
```

Generate a random MAC and apply:

```bash
sudo python3 mac_changer.py change eth0 --random --apply
```

Notes on security
- The script never uses shell=True and always passes command arguments as lists to subprocess.
- Inputs are validated with regexes and interfaces are confirmed to exist under `/sys/class/net`.
- The script still requires root to change MACs; running as an attacker with root grants full control and is out of scope.

Limitations
- Linux-only (uses `ip` and `/sys/class/net`).
- Does not protect the script file from modification; to prevent tampering, run from immutable media or use system-level protections.
