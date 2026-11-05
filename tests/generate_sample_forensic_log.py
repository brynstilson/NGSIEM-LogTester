"""Regenerates samples/forensic-log-sample.jsonl by running the real app against the mock API.

Run from the application directory: python tests/generate_sample_forensic_log.py
"""
import getpass
import sys
import threading
from pathlib import Path

from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from app import create_app
from falcon_client import FalconClient
from forensic_log import ForensicLog
from mock_falcon import MockFalcon
from workflow import Settings

OUTPUT = ROOT / "samples" / "forensic-log-sample.jsonl"
LOGIN_EVENT = '{"eventType":"user.session.start","actor":{"alternateId":"alice@example.com"},"outcome":{"result":"SUCCESS"}}'
S3_EVENT = '{"eventName":"GetObject","bucket":"example-bucket","status":200}'
BAD_EVENT ='{"eventType":"user.session.end","actor":{"alternateId":"bob@example.com"}}'


def main():
    OUTPUT.unlink(missing_ok=True)
    getpass.getuser = lambda: "sample-operator"  # Keep the real OS user out of a shareable file.
    mock = MockFalcon()
    server = make_server("127.0.0.1", mock.port, mock.app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = FalconClient("sample-api-client-id", "sample-client-secret", f"http://127.0.0.1:{mock.port}")
    settings = Settings(
        token_poll_seconds=0.2, ingest_retry_seconds=0.2, ingest_ready_wait_seconds=0.2, cleanup_retry_seconds=0.2
    )
    web = create_app(client, settings, ForensicLog(OUTPUT)).test_client()

    def submit(log, connector_id="conn-okta"):
        return web.post("/api/submit", json={"connector_id": connector_id, "log": log, "mode": "event"}).get_json()

    # 1. Everything works.
    print(submit(LOGIN_EVENT)["message"])
    # 1a. A pull connector is tested through a temporary HEC clone with the same parser.
    print(submit(S3_EVENT, "conn-s3")["message"])
    # 2. The ingest endpoint rejects the log, and the clone is still cleaned up.
    mock.not_ready_polls = 0
    mock.ingest_statuses = [400]
    print(submit(BAD_EVENT)["message"])
    # 3. The log is accepted, but the clone can't be deleted.
    mock.delete_statuses = [500, 500, 500]
    print(submit(LOGIN_EVENT)["message"])
    # 4. The clone's name doesn't match what was requested, so the delete limiter refuses it.
    mock.rename_clones = True
    print(submit(LOGIN_EVENT)["message"])
    server.shutdown()


if __name__ == "__main__":
    main()
