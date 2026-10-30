# Install ESP32-C6 Guard

## Existing device: update over Wi-Fi

Open the ESP LAN address, log in, then choose **Settings → Firmware OTA → Check updates → Update over Wi-Fi**. Use this path for normal upgrades; it preserves the existing settings/rules/filter formats. Keep power connected until the ESP restarts and shows the new version. The separate OTA BIN is for manual app upload, not a complete first installation.

## First USB installation

1. Use **ESP32-C6 / 16 MB flash**. Connect it to your computer with a USB data cable. Back up an existing device before first flashing.
2. Download the **Setup ZIP** from the release and extract it into a writable folder. Install Python **3.10+** from https://www.python.org/downloads/ if it is not already available.
3. Windows: run `setup.cmd`, or open a terminal in that folder and run `py -3 setup.py`. macOS/Linux: open a terminal in that folder and run `python3 setup.py`; `setup.command` is also included for macOS.
4. The helper checks every firmware file against its manifest. Type **INSTALL** to continue. On its first run it downloads pinned esptool into a local `.guard-tools` environment; Internet is required for that step. It does not change the system Python installation.
5. Select the ESP USB port. The helper checks the chip and detected flash size, then writes only the packaged flash offsets. It does not erase the whole chip or program eFuses. Do not disconnect power while writing.
6. After restart, follow the Wi-Fi setup below.

To specify a port directly: `python3 setup.py --port YOUR_SERIAL_PORT` (Windows: `py -3 setup.py --port COM3`). To check downloaded files without Internet, tools or hardware: `python3 setup.py --check`.

If no port appears, check the data cable and USB/serial driver. If automatic connection fails, hold BOOT while pressing/releasing RESET, release BOOT, then retry the helper. Use the board manufacturer's instructions if its buttons differ. A chip/flash-size mismatch stops installation before writing.

`flash-manifest.json` contains exact offsets, sizes and SHA-256 hashes for manual esptool installation. **Do not change the offsets or mix files from different releases.** A Source ZIP must be built before it can be flashed; it is not the Setup ZIP.

## Wi-Fi setup

1. Join **C6-Guard-...**, Wi-Fi password **12345678**; stay connected if your phone says there is no Internet.
2. Open **http://192.168.8.8** and select **VI / EN**. Set your own admin password, then scan/select the router's **2.4 GHz** Wi-Fi.
3. Save the LAN IP shown. Reconnect the phone/computer to the router, open that LAN IP and log in. The setup AP closes after connection.
4. Reserve the IP on the router, or configure an unused static LAN address in Settings. Point intended clients/router DNS to the ESP LAN IP.

Hold BOOT for about 3 seconds to reopen recovery Wi-Fi; existing admin credentials and rules are preserved. The public AP key does not log you into the admin page. If the router also uses 192.168.8.0/24, the setup subnet can overlap; use a different LAN subnet for this beta.

## Hướng dẫn nhanh bằng tiếng Việt

- Đang dùng ESP: cập nhật ở **Settings → Firmware OTA**, không dùng gói nạp USB để nâng cấp thông thường.
- Cài mới: giải nén **Setup ZIP**, cài Python 3.10+, chạy `setup.cmd` (Windows) hoặc `python3 setup.py` (Mac/Linux). Nhập **INSTALL**, chọn cổng USB. Công cụ tự tải esptool vào thư mục riêng và kiểm tra đúng ESP32-C6/16 MB trước khi ghi.
- Sau khi nạp: nối **C6-Guard-... / 12345678**, vào **192.168.8.8**, chọn **VI**, tự đặt mật khẩu admin, quét và chọn Wi-Fi nhà. Sau đó dùng IP LAN router cấp để vào trang quản lý.
- Giữ nguồn khi nạp/cập nhật. Gói USB ghi firmware và bộ lọc mặc định; hãy backup trước nếu board đã có dữ liệu. Giữ BOOT khoảng 3 giây để mở lại AP khi cần sửa Wi-Fi.
