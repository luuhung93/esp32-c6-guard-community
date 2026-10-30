# Licenses and attribution

Original firmware, web UI, build/install tools and user documentation: GPL-3.0-only, copyright © 2026 luuhung93. This does not relicense third-party code or filter data.

| Component | License / notice |
| --- | --- |
| ESP-IDF v5.5.2 | Apache-2.0 and component terms; `LICENSES/ESP-IDF-Apache-2.0.txt` and `LICENSES/ESP-IDF-component-NOTICES.txt` |
| Tailwind CSS | MIT; `LICENSES/TailwindCSS-MIT.txt` |
| Vite | MIT and bundled notices; `LICENSES/Vite-NOTICES.md` |
| Heroicons inline SVGs | MIT; `LICENSES/Heroicons-MIT.txt` |
| AdAway starter domains | CC-BY-3.0; `LICENSES/AdAway-CC-BY-3.0.txt` |

AdAway attribution: Kicelo, Dominik Schuermann and contributors. Source: https://github.com/AdAway/adaway.github.io/ . Its original header is retained in `data/default-domains.txt`. The build tool normalizes/deduplicates hostnames and compiles sorted 64-bit SHA-256 prefixes into the default starter data.

SDK source: https://github.com/espressif/esp-idf/tree/v5.5.2 at commit `30aaf64524299d3bde422ca9a2848090d1bc5d0f`; cJSON submodule `c859b25da02955fef659d658b8f324b5cde87be3`. The SDK is external, not vendored. Exact Web build dependencies are pinned in `web/package-lock.json`; upstream packages retain their notices. The setup helper downloads esptool 4.12.0 into its local environment when run; esptool retains its upstream GPL-2.0-or-later license.

Optional country filters are separate downloads from https://luuhung93.github.io/esp32-c6-guard-filters/ . Their catalog/source/license notices apply independently; some sources have noncommercial terms. They are not bundled or relicensed by this source/setup package.

Setup ZIPs include these notices. The official private signing key is excluded. Modified builds can be installed via USB using your own generated key; see README. No eFuse provisioning is required.
