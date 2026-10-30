"""First-install helper. --check validates files without touching a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import venv

OFFSETS = {"bootloader.bin": 0, "partition-table.bin": 0x8000,
           "ota_data_initial.bin": 0x109000, "esp32-c6-guard.bin": 0x110000,
           "filters.bin": 0x610000}

LIMITS = {"bootloader.bin": 0x8000, "partition-table.bin": 0x1000,
          "ota_data_initial.bin": 0x2000, "esp32-c6-guard.bin": 0x280000,
          "filters.bin": 0x900000}


def validate_package(root):
    root = Path(root).resolve()
    manifest = json.loads((root / "flash-manifest.json").read_text())
    if manifest.get("chip") != "esp32c6" or manifest.get("flashSize") != "16MB":
        raise ValueError("This setup requires an ESP32-C6 / 16 MB package")
    entries = manifest.get("files", [])
    if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
        raise ValueError("Invalid file manifest")
    if len(entries) != len(OFFSETS) or {e.get("file") for e in entries} != set(OFFSETS):
        raise ValueError("Incomplete first-install package")
    end = 0
    for entry in sorted(entries, key=lambda e: int(e["offset"], 0)):
        name = entry["file"]
        offset = int(entry["offset"], 0)
        path = root / name
        if offset != OFFSETS[name] or path.resolve().parent != root or offset < end:
            raise ValueError("Invalid package path or flash offset")
        data = path.read_bytes()
        if not data or len(data) > LIMITS[name] or len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Package integrity check failed: " + name)
        end = offset + len(data)
        if end > 16 * 1024 * 1024:
            raise ValueError("Package exceeds 16 MB flash")
    return manifest


def tool_python(root):
    folder = root / ".guard-tools"
    python = folder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.exists():
        print("Preparing local flash tools (Internet required; system Python is unchanged)...", flush=True)
        venv.EnvBuilder(with_pip=True).create(folder)
    check = subprocess.run([str(python), "-c", "import esptool; assert esptool.__version__ == '4.12.0'"], capture_output=True)
    if check.returncode:
        subprocess.run([str(python), "-m", "pip", "install", "esptool==4.12.0"], check=True)
    return str(python)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check package only; no downloads or serial access")
    parser.add_argument("--port", help="ESP USB serial port")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = validate_package(root)
    print("C6 Guard " + manifest["version"] + " / ESP32-C6 / 16 MB: package integrity OK", flush=True)
    if args.check:
        return 0
    print("First USB installation writes firmware and starter filters. Use Wi-Fi OTA for ordinary upgrades.")
    print("Back up any existing device before continuing. No full-chip erase or eFuse programming is performed.")
    if input("Continue with first installation? Type INSTALL: ").strip() != "INSTALL":
        print("Cancelled; no device was accessed.")
        return 0
    python = tool_python(root)
    port = args.port
    if not port:
        command = "import json; from serial.tools.list_ports import comports; print(json.dumps([(p.device,p.description) for p in comports()]))"
        ports = json.loads(subprocess.check_output([python, "-c", command], text=True))
        if not ports:
            raise ValueError("No USB serial port found. Connect the ESP with a data cable and try again.")
        for i, (device, description) in enumerate(ports, 1):
            print(f"{i}. {device} - {description}")
        selected = input("ESP port number: ").strip()
        if not selected.isdigit() or not 1 <= int(selected) <= len(ports):
            raise ValueError("Invalid port selection")
        port = ports[int(selected) - 1][0]
    base = [python, "-m", "esptool", "--chip", "esp32c6", "--port", port, "--baud", "230400"]
    probe = subprocess.run(base + ["flash_id"], capture_output=True, text=True, check=True)
    print(probe.stdout, end="")
    if not re.search(r"Detected flash size:\s*16MB\b", probe.stdout):
        raise ValueError("Expected 16 MB flash; installation stopped before writing")
    files = []
    for entry in sorted(manifest["files"], key=lambda e: int(e["offset"], 0)):
        files.extend([entry["offset"], str(root / entry["file"])])
    subprocess.run(base + ["write_flash", "--flash_size", "16MB", "--flash_mode", "dio", "--flash_freq", "80m"] + files, check=True)
    print("Installed. Join C6-Guard-... / password 12345678, then open http://192.168.8.8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        raise SystemExit(130)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("Setup failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
