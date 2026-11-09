import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app_settings import DEFAULT_TITLE, AppSettings
from falcon_client import FalconClient
from forensic_log import ForensicLog

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
HEADERS = {"X-Requested-By": "ngsiem-logtester"}


@pytest.fixture
def paths(tmp_path):
    return {"settings": tmp_path / "app_settings.json", "branding": tmp_path / "branding",
            "forensic": tmp_path / "logs" / "forensic.jsonl"}


def make_app(paths, password=""):
    client = FalconClient("id", "secret", "http://127.0.0.1:1", timeout=1)
    return create_app(client, forensic=ForensicLog(paths["forensic"]),
                      app_settings=AppSettings(paths["settings"], paths["branding"]), admin_password=password)


@pytest.fixture
def web(paths):
    return make_app(paths).test_client()


def save(web, headers=HEADERS, **values):
    return web.post("/api/settings", json=values, headers=headers)


def upload(web, data, headers=HEADERS, name="logo.png"):
    return web.post("/api/settings/logo", data={"logo": (io.BytesIO(data), name)},
                    headers=headers, content_type="multipart/form-data")


def test_defaults_before_anything_is_saved(web):
    settings = web.get("/api/settings").get_json()["settings"]
    assert settings["title"] == DEFAULT_TITLE
    assert settings["logo_url"] is None
    assert settings["password_required"] is False


def test_title_and_contact_details_are_saved(web, paths):
    response = save(web, title="  Acme   SOC Log Tester ", contact_name="SOC Team", contact_email="soc@example.com",
                    contact_phone="+1 (555) 010-0000 x12", contact_note="Weekdays 9-5.\nUrgent: page on-call.")
    assert response.status_code == 200, response.get_json()
    settings = web.get("/api/settings").get_json()["settings"]
    assert settings["title"] == "Acme SOC Log Tester"
    assert settings["contact_note"] == "Weekdays 9-5.\nUrgent: page on-call."
    assert json.loads(paths["settings"].read_text())["contact_email"] == "soc@example.com"


def test_a_blank_title_falls_back_to_the_default(web):
    save(web, title="")
    assert web.get("/api/settings").get_json()["settings"]["title"] == DEFAULT_TITLE


@pytest.mark.parametrize("values,message", [
    ({"title": "x" * 81}, "at most 80"),
    ({"contact_email": "not-an-email"}, "email"),
    ({"contact_phone": "call me maybe"}, "phone"),
    ({"title": 5}, "must be text"),
    ({"contact_name": "a\x07b"}, "control characters"),
])
def test_invalid_values_are_refused(web, values, message):
    response = save(web, **values)
    assert response.status_code == 400
    assert message in response.get_json()["message"]


def test_settings_changes_need_the_custom_header(web):
    assert save(web, headers={}, title="x").status_code == 400
    assert upload(web, PNG, headers={}).status_code == 400


def test_an_admin_password_is_enforced_when_set(paths):
    web = make_app(paths, password="correct horse").test_client()
    assert web.get("/api/settings").get_json()["settings"]["password_required"] is True
    assert save(web, title="x").status_code == 403
    assert save(web, headers={**HEADERS, "X-Admin-Password": "wrong"}, title="x").status_code == 403
    assert upload(web, PNG).status_code == 403
    assert save(web, headers={**HEADERS, "X-Admin-Password": "correct horse"}, title="Mine").status_code == 200
    assert web.get("/api/settings").get_json()["settings"]["title"] == "Mine"


@pytest.mark.parametrize("data,extension", [(PNG, "png"), (JPEG, "jpg"), (WEBP, "webp"), (b"GIF89a" + b"\x00" * 16, "gif")])
def test_logo_upload_is_served_with_safe_headers(web, paths, data, extension):
    response = upload(web, data)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["settings"]["logo_url"] == "/branding/logo"
    served = web.get("/branding/logo")
    assert served.data == data
    assert served.headers["X-Content-Type-Options"] == "nosniff"
    assert served.headers["Content-Security-Policy"] == "default-src 'none'"
    assert [p.name for p in paths["branding"].iterdir()] == [f"logo.{extension}"]


@pytest.mark.parametrize("data,message", [
    (SVG, "PNG, JPEG, GIF or WebP"),
    (b"RIFF\x00\x00\x00\x00WAVEfmt ", "PNG, JPEG, GIF or WebP"),
    (b"", "empty"),
    (b"\x89PNG\r\n\x1a\n" + b"\x00" * (1024 * 1024), "1 MB"),
])
def test_unsafe_or_oversized_logos_are_refused(web, paths, data, message):
    response = upload(web, data, name="logo.svg")
    assert response.status_code == 400
    assert message in response.get_json()["message"]
    assert not paths["branding"].exists() or not any(paths["branding"].iterdir())


def test_a_new_logo_replaces_the_old_one(web, paths):
    upload(web, PNG)
    upload(web, JPEG)
    assert [p.name for p in paths["branding"].iterdir()] == ["logo.jpg"]


def test_the_logo_can_be_removed(web, paths):
    upload(web, PNG)
    response = save(web, remove_logo=True)
    assert response.get_json()["settings"]["logo_url"] is None
    assert web.get("/branding/logo").status_code == 404
    assert not any(paths["branding"].iterdir())


def test_no_logo_is_a_404(web):
    assert web.get("/branding/logo").status_code == 404


def test_changes_are_recorded_in_the_forensic_log(web, paths):
    save(web, title="Acme", contact_email="soc@example.com")
    save(web, title="Acme")  # Nothing changed, so nothing is recorded.
    upload(web, PNG)
    rows = [json.loads(line) for line in paths["forensic"].read_text().splitlines()]
    assert [r["event"] for r in rows] == ["settings_changed", "settings_changed"]
    assert rows[0]["changes"] == {"title": "Acme", "contact_email": "soc@example.com"}
    assert rows[1]["changes"]["logo"]["bytes"] == len(PNG)
    assert "sha256" in rows[1]["changes"]["logo"]


def test_a_tampered_settings_file_cant_point_the_logo_elsewhere(web, paths):
    paths["settings"].write_text(json.dumps({"logo": "../../app.py"}))
    assert web.get("/api/settings").get_json()["settings"]["logo_url"] is None
    assert web.get("/branding/logo").status_code == 404


def test_the_page_has_the_settings_button_and_dropdown_controls(web):
    html = web.get("/").get_data(as_text=True)
    for marker in ('id="settings-open"', 'id="settings-dialog"', 'id="templates-toggle"', "function enhanceSelect"):
        assert marker in html


def test_the_saved_title_is_in_the_first_paint_and_escaped(web):
    save(web, title='Acme <script>alert(1)</script>')
    html = web.get("/").get_data(as_text=True)
    assert "<title>Acme &lt;script&gt;alert(1)&lt;/script&gt;</title>" in html
    assert "<script>alert(1)</script>" not in html


def test_listen_address_defaults_to_localhost():
    from app import listen_address
    assert listen_address({}) == ("127.0.0.1", 5000, [])
    assert listen_address({"HOST": "", "PORT": ""}) == ("127.0.0.1", 5000, [])


def test_listen_address_warns_when_reachable_from_other_machines():
    from app import listen_address
    host, port, warnings = listen_address({"HOST": "0.0.0.0", "PORT": "8080"})
    assert (host, port) == ("0.0.0.0", 8080)
    assert len(warnings) == 2 and "other machines" in warnings[0] and "APP_ADMIN_PASSWORD" in warnings[1]
    _, _, warnings = listen_address({"HOST": "0.0.0.0", "APP_ADMIN_PASSWORD": "x"})
    assert len(warnings) == 1
