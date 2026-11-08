# WiFi Security Lab

Android Wi-Fi security assessment companion for authorized home and university labs.

## Current scope
- Android 10–16 target range (runtime behavior varies by Android/OEM).
- Wi-Fi scan results: SSID, BSSID, frequency/band, RSSI, and advertised security capabilities.
- Local security assessment based on advertised security mode.
- WPS status is explicitly reported as **unknown** when Android does not expose it. Android's public Wi-Fi scan API does not provide a reliable WPS-PIN audit interface.
- Manual router inventory for TP-Link, D-Link, and NETIS, including NETIS NC21 (HW V2 / FW V4.0).
- Exportable plain-text assessment report.
- GitHub Actions builds a debug APK and uploads it as an artifact.

## Safety and technical limits
This app does not brute-force WPS PINs, guess Wi-Fi passwords, capture handshakes, deauthenticate clients, or attempt access to networks. Use it only on networks you own or are explicitly authorized to assess.

A normal Android app without root cannot perform every low-level 802.11/WPS operation. Android scan throttling, location permissions, OEM firmware, and hardware can limit scan results. WPS state cannot be inferred from SSID/security capability strings; use the router's admin interface or a dedicated authorized lab instrument to verify it.

## Build
Open this repository in Android Studio (JDK 17 recommended), or run:
```bash
./gradlew assembleDebug
```
The APK is produced at `app/build/outputs/apk/debug/app-debug.apk`.

## GitHub Actions
Push to `main` or manually run **Android APK** in Actions. Download the `wifi-security-lab-debug-apk` artifact.

## Device
Designed for phones including Xiaomi Mi 10T Pro / Android 12. On first scan, grant Nearby Wi-Fi / Location permissions as requested and enable Location services if Android requires it.
