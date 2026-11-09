"""Administrator settings: a company logo, header title, and contact information.

Settings live in app_settings.json and the logo in branding/, both in the application directory and
both left out of Git, so each installation keeps its own.
"""
import json
import os
import re
import threading
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DEFAULT_TITLE = "NG-SIEM Log Tester"
MAX_LOGO_BYTES = 1024 * 1024
# Raster images only. An SVG can carry script, and the logo is served from the app's own origin.
LOGO_TYPES = {
    "png": (b"\x89PNG\r\n\x1a\n", "image/png"),
    "jpg": (b"\xff\xd8\xff", "image/jpeg"),
    "gif": (b"GIF8", "image/gif"),
    "webp": (b"RIFF", "image/webp"),
}
FIELDS = {
    "title": 80,
    "contact_name": 80,
    "contact_email": 120,
    "contact_phone": 40,
    "contact_note": 300,
}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE = re.compile(r"^[0-9+()\-.\s x]*$")


class SettingsError(ValueError):
    """A value an administrator entered that can't be saved."""


class AppSettings:
    def __init__(self, path=None, logo_dir=None):
        self.path = Path(path or os.environ.get("APP_SETTINGS_PATH") or APP_DIR / "app_settings.json").resolve()
        self.logo_dir = Path(logo_dir or os.environ.get("APP_BRANDING_DIR") or APP_DIR / "branding").resolve()
        self._lock = threading.Lock()

    def read(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        values = {key: str(data.get(key) or "") for key in FIELDS}
        values["title"] = values["title"] or DEFAULT_TITLE
        values["logo"] = data.get("logo") if self.logo_path(data.get("logo")) else None
        return values

    def logo_path(self, name):
        if not name or not re.fullmatch(r"logo\.(png|jpg|gif|webp)", str(name)):
            return None
        path = self.logo_dir / name
        return path if path.is_file() else None

    def update(self, values):
        """Validate and save text fields. Returns the fields that changed."""
        cleaned = {}
        for key, limit in FIELDS.items():
            if key not in values:
                continue
            value = values[key]
            if not isinstance(value, str):
                raise SettingsError(f"{key} must be text.")
            value = " ".join(value.split()) if key != "contact_note" else value.strip()
            if len(value) > limit:
                raise SettingsError(f"{key.replace('_', ' ').capitalize()} can be at most {limit} characters.")
            if any(ord(c) < 32 and c not in "\n\t" for c in value):
                raise SettingsError(f"{key.replace('_', ' ').capitalize()} contains control characters.")
            cleaned[key] = value
        if cleaned.get("contact_email") and not EMAIL.match(cleaned["contact_email"]):
            raise SettingsError("The contact email doesn't look like an email address.")
        if cleaned.get("contact_phone") and not PHONE.match(cleaned["contact_phone"]):
            raise SettingsError("The contact phone can only contain digits, spaces and + ( ) - . x")
        with self._lock:
            current = self._raw()
            changed = {k: v for k, v in cleaned.items() if current.get(k, "") != v}
            current.update(cleaned)
            self._write(current)
        return changed

    def set_logo(self, data):
        """Save an uploaded logo after checking its type and size. Returns its file name."""
        if not data:
            raise SettingsError("The logo file is empty.")
        if len(data) > MAX_LOGO_BYTES:
            raise SettingsError("The logo can be at most 1 MB.")
        extension = next((ext for ext, (magic, _) in LOGO_TYPES.items() if data.startswith(magic)), None)
        if extension == "webp" and data[8:12] != b"WEBP":
            extension = None
        if not extension:
            raise SettingsError("The logo must be a PNG, JPEG, GIF or WebP image.")
        name = f"logo.{extension}"
        with self._lock:
            self.logo_dir.mkdir(parents=True, exist_ok=True)
            for old in self.logo_dir.glob("logo.*"):
                old.unlink()
            (self.logo_dir / name).write_bytes(data)
            current = self._raw()
            current["logo"] = name
            self._write(current)
        return name

    def remove_logo(self):
        with self._lock:
            for old in self.logo_dir.glob("logo.*"):
                old.unlink()
            current = self._raw()
            current.pop("logo", None)
            self._write(current)

    def content_type(self, name):
        extension = str(name).rsplit(".", 1)[-1]
        return LOGO_TYPES[extension][1]

    def _raw(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temporary.replace(self.path)
