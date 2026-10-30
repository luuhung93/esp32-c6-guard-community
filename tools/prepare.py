"""Build the default starter; create a local signing key only when requested."""
import argparse
import collections
import hashlib
import ipaddress
from pathlib import Path
import re
import struct
import subprocess
import sys
HEADER = struct.Struct("<4sBBBB64sII32s32s")
MAX_DOMAINS = 500_000
def normalize_domain(text):
    text = text.removesuffix(".").lower()
    if not text or len(text) > 253 or not text.isascii():
        raise ValueError("Use an ASCII DNS name or punycode A-label")
    for label in text.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Invalid DNS label")
    return text

def domain_hash(domain, bits=64):
    return int.from_bytes(hashlib.sha256(domain.encode("ascii")).digest()[:bits//8], "little")

def parse_lines(lines, cap=MAX_DOMAINS):
    domains, skipped = set(), collections.Counter()
    for raw in lines:
        line = raw.split(" #",1)[0].strip()
        if not line or line.startswith(("#", "!", "[")): continue
        if line.startswith("@@"):
            skipped["exception"] += 1; continue
        if any(c in line for c in ("$", "##", "#@#", "*", "/", "|http")):
            skipped["unsupported"] += 1; continue
        if line.startswith("||") and line.endswith("^"):
            candidates = [line[2:-1]]
        else:
            parts = line.split("#", 1)[0].split()
            if not parts: continue
            try:
                ipaddress.ip_address(parts[0]); candidates = parts[1:]
            except ValueError:
                candidates = parts if len(parts) == 1 else []
        if not candidates: skipped["invalid"] += 1
        for candidate in candidates:
            try:
                name = normalize_domain(candidate)
                if name in ("localhost", "localhost.localdomain"): continue
                try: ipaddress.ip_address(name)
                except ValueError: domains.add(name)
            except ValueError: skipped["invalid"] += 1
        if len(domains) > cap: raise ValueError("Domain limit exceeded")
    return domains, dict(skipped)

def build_filter(source_id, domains, hash_bits=64):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", source_id) or hash_bits not in (40, 64):
        raise ValueError("Invalid ID or hash width")
    names = sorted({normalize_domain(d) for d in domains})
    if not names: raise ValueError("Refusing empty filter")
    width = hash_bits // 8
    hashes = sorted({domain_hash(d, hash_bits) for d in names})
    payload = b"".join(h.to_bytes(width, "little") for h in hashes)
    source_digest = hashlib.sha256(("\n".join(names)+"\n").encode()).digest()
    return HEADER.pack(b"C6GF", 1, 1, width, 0, source_id.encode(), len(hashes), len(payload), source_digest, hashlib.sha256(payload).digest()) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development-key", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    domains, _ = parse_lines((root / "data/default-domains.txt").read_text().splitlines())
    (root / "factory").mkdir(exist_ok=True)
    (root / "factory/starter.bin").write_bytes(build_filter("guard-starter", domains))
    if args.development_key:
        key = root / "keys/firmware.pem"
        key.parent.mkdir(exist_ok=True)
        if not key.exists():
            subprocess.run([sys.executable, "-m", "espsecure", "generate_signing_key", "--version", "2", str(key)], check=True)
            key.chmod(0o600)
    print("Starter prepared; keep your private signing key outside Git.")

if __name__ == "__main__":
    main()
