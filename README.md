# ESP32-C6 Guard

A small DNS ad/tracker blocker for your local network, with an offline **English / Vietnamese** web interface.

**Author:** [@luuhung93](https://github.com/luuhung93) · **Version:** 0.2.21 Community Beta · **Code:** GPL-3.0-only

## Download and install

Open [Releases](https://github.com/luuhung93/esp32-c6-guard-community/releases) and choose:

- **Setup ZIP** — ready-to-install firmware and a USB setup helper. Extract the ZIP, install Python 3.10+ if needed, then run `setup.cmd` on Windows or `python3 setup.py` on macOS/Linux. No ESP-IDF or Node.js is needed. See [SETUP.md](SETUP.md).
- **Source ZIP** — the complete firmware/Web source and build inputs for your own changes. Build instructions are below.
- **OTA BIN** — app-only update for an existing installation using the official signing identity. On the ESP, use **Settings → Firmware OTA → Check updates → Update over Wi-Fi**.

Hardware: **ESP32-C6 with 16 MB flash**, 2.4 GHz Wi-Fi. Tested on MuseLab nanoESP32-C6 v1.0 (onboard RGB GPIO8, BOOT GPIO9). Other ESP32 variants and smaller flash sizes are unsupported.

## First setup

1. Power the board and join **C6-Guard-...**, Wi-Fi password **12345678**.
2. Open **http://192.168.8.8**. Select **VI / EN**, then choose an admin password (12–128 characters).
3. Scan/select your router Wi-Fi and connect. Note the LAN IP shown.
4. Return your phone/computer to the router network and open the ESP LAN IP. Log in with your admin password.
5. Reserve the address on your router, or choose an unused static address in Settings. Set the ESP LAN IP as DNS for your intended devices/router.

Language selection is saved in the browser. The setup address is available on the ESP Wi-Fi; it is not a fixed alias on every home network. Hold **BOOT for about 3 seconds** to reopen the recovery AP without resetting admin/rules.

AdAway is included by default. Search for optional country filters, including hostsVN; at most **five lists** may be installed. Installing turns a list on; Off removes its data. Custom allow/block rules support up to **1,000 entries**; export them before replacing by import. Query history and counters reset on reboot.

## Build your own source

Install [ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/get-started/) with ESP32-C6 support, Node.js 22.12+, npm and Git. Activate the ESP-IDF shell/Python environment, then run from the source folder:

```sh
npm --prefix web ci
npm --prefix web run build
python tools/prepare.py --development-key
idf.py build
```

For a first USB installation after backup:

```sh
idf.py -p YOUR_SERIAL_PORT -b 230400 flash
```

Keep the generated ignored `keys/firmware.pem` for your future builds. There is no official private key in this source. Self-built apps have a different signing identity and cannot accept official OTA; use your own matching-key app or reinstall through USB after backup. No security eFuses are programmed. Edit the C source in `main/`, the UI in `web/`, or starter domains in `data/default-domains.txt`, then rebuild. For another C6 board, configure the LED pin using `idf.py menuconfig`, or disable it.

## Limits and security

This is a DNS server, not a router or DHCP server. DoH/Private DNS and alternate DNS can bypass filtering. Management uses HTTP on a trusted LAN; do not expose it to the Internet. The public setup Wi-Fi key is separate from your private admin password.

Community Beta: paced LAN tests at 20–50 queries/second passed, but immediate 30-worker bursts still had timeouts/SERVFAIL and then recovered. This does not guarantee capacity for 30 physical devices. Long-term multi-device soak, power-cut recovery and the complete OTA rollback matrix remain pending. Keep power connected during updates.

## Tiếng Việt

Tải **Setup ZIP** để cài qua USB, hoặc cập nhật thiết bị đang dùng tại **Settings → Firmware OTA**. Sau khi cài, nối Wi-Fi **C6-Guard-... / 12345678**, mở **192.168.8.8**, tự đặt mật khẩu admin rồi kết nối Wi-Fi nhà. Chọn **VI / EN** để đổi ngôn ngữ. Dùng IP LAN do router cấp để truy cập các lần sau. Hướng dẫn chi tiết nằm trong **SETUP.md** và gói Setup.

## License and support

Original code is [GPL-3.0-only](LICENSE), copyright © 2026 luuhung93. Frameworks, icons and filter data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md) and `LICENSES/`. Public country data and its notices are served separately at https://luuhung93.github.io/esp32-c6-guard-filters/ .

Open an issue with board model, firmware version and reproduction steps. Do not post passwords, private keys, session cookies, device backups or private query history. See [SECURITY.md](SECURITY.md) for vulnerability reporting.
