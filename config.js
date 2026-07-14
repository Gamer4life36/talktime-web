// API base URL.
//  - Empty string ("") => same-origin (web app served by this server).
//  - Absolute URL       => used by the packaged Android APK to reach the server.
// Can be overridden at runtime via the "Server address" field (localStorage).
// Permanent ngrok domain -> this PC's LOCAL server, so the app works from any
// network / Wi-Fi anywhere and the URL never changes (survives reboots). The
// server + all data stay on this PC (E:).
window.WHISPER_API_BASE = "https://mystified-vacate-aftermath.ngrok-free.dev";

// The server's PUBLIC signing key (safe to ship -- it is NOT a secret). The app
// pins it to verify the ECDH handshake, so no shared key ever lives in the APK.
window.WHISPER_SERVER_PUB = "BBzTOuEHCy/hVu4qGEfhUmtZM3noTyFOTEEsdht/bdULtKZsSONJmgOpZeqqa+qRX7vP7tUsWObIe8o6UWtcGy4=";
