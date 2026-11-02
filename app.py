"""Operator web app for testing a raw JSON log against a clone of an NG-SIEM data connector."""
import getpass
import hashlib
import os
import uuid

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from falcon_client import ActivityLog, FalconClient, FalconError
from forensic_log import ForensicLog
from workflow import MODE_EVENT, MODE_RAW, Settings, is_pull, submit_log


def _summary(connection):
    return {
        "id": connection.get("id"),
        "name": connection.get("name"),
        "parser": connection.get("parser_name"),
        "status": connection.get("status"),
        "source_type": connection.get("source_type"),
        "vendor_name": connection.get("vendor_name"),
        "vendor_product_name": connection.get("vendor_product_name"),
        "can_ingest": not is_pull(connection),
    }


def create_app(client=None, settings=None, forensic=None):
    app = Flask(__name__)
    settings = settings or Settings()
    forensic = forensic or ForensicLog()
    client = client or FalconClient(
        os.environ.get("FALCON_CLIENT_ID"),
        os.environ.get("FALCON_CLIENT_SECRET"),
        os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    selected = {}  # connection ID -> details read when the operator selected it

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/connectors")
    def list_connectors():
        log = ActivityLog()
        try:
            connections = client.list_connections(log)
        except FalconError as exc:
            log.error(str(exc))
            return jsonify(success=False, message=str(exc), log=log.entries)
        connectors = sorted((_summary(c) for c in connections), key=lambda c: (c["name"] or "").lower())
        return jsonify(success=True, connectors=connectors, log=log.entries)

    @app.get("/api/connectors/<connection_id>/parser")
    def select_connector(connection_id):
        log = ActivityLog()
        try:
            connection = client.get_connection(connection_id, log)
        except FalconError as exc:
            log.error(str(exc))
            return jsonify(success=False, message=str(exc), log=log.entries)
        selected[connection_id] = connection
        return jsonify(success=True, connector=_summary(connection), log=log.entries)

    @app.post("/api/submit")
    def submit():
        # Requiring a JSON body means another site can't trigger this without a CORS preflight.
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request.", log=[]), 415
        log = ActivityLog()
        connection_id = data.get("connector_id")
        mode = data.get("mode", MODE_EVENT)
        text = data.get("log") if isinstance(data.get("log"), str) else ""
        submission_id = str(uuid.uuid4())

        # No forensic record means no tenant change, so this write has to succeed first.
        try:
            forensic.write(
                "submission_started",
                submission_id,
                operator=getpass.getuser(),
                remote_addr=request.remote_addr,
                api_client_id=client.client_id,
                falcon_base_url=client.base_url,
                connector_id=connection_id,
                mode=mode,
                log_sha256=hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
                submitted_log=text,
            )
        except OSError as exc:
            message = f"Nothing was sent or cloned, because the forensic log can't be written: {exc}"
            log.error(message)
            return jsonify(success=False, message=message, log=log.entries)
        log.info(f"Forensic record {submission_id} opened in {forensic.path.name}")

        unwritten = []

        def record(event, **fields):
            try:
                forensic.write(event, submission_id, **fields)
            except OSError as exc:
                unwritten.append(event)
                log.error(f"Could not write forensic record {event}", str(exc))

        connection = selected.get(connection_id)
        clone = None
        try:
            if mode not in (MODE_EVENT, MODE_RAW):
                raise FalconError(f"Unknown send mode: {mode}")
            if connection is None:
                if not connection_id:
                    raise FalconError("Select a data connector first.")
                connection = selected[connection_id] = client.get_connection(connection_id, log)
            clone = submit_log(client, connection, text, mode, settings, log, record)
            success = True
            message = f"Log accepted by cloned connector {clone['name']}, and the clone was deleted."
            log.info(message)
        except FalconError as exc:
            success = False
            message = str(exc)
            log.error(message)
        except Exception as exc:  # The forensic record must still be closed.
            success = False
            message = f"Unexpected {type(exc).__name__}. See the verbose log for details."
            log.error(message, str(exc))

        record(
            "submission_finished",
            success=success,
            message=message,
            source_connector=_summary(connection) if connection else None,
            clone=clone,
            activity=log.entries,
        )
        if unwritten:
            message += f" WARNING: the forensic log is incomplete, missing: {', '.join(unwritten)}."
        return jsonify(success=success, message=message, submission_id=submission_id, clone=clone, log=log.entries)

    return app


if __name__ == "__main__":
    load_dotenv()
    # Bound to localhost only: the app has no login, and it acts with the API client's rights.
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), threaded=True)
