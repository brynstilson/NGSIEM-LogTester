"""A stand-in for the Falcon API and an HEC ingest endpoint, for tests and UI demos.

Response shapes follow CrowdStrike's published gofalcon models and Terraform provider.
Run it directly to demo the UI: python tests/mock_falcon.py, then set
FALCON_BASE_URL=http://127.0.0.1:9000 with any client ID and secret.
"""
from flask import Flask, jsonify, request

HEC_CONNECTOR = {
    "id": "cat-hec", "name": "HEC / HTTP Event Connector", "type": "PUSH", "parsers": ["json"],
    "vendor_name": "Generic", "vendor_product_name": "HEC", "log_sources": [],
}
OKTA_CONNECTOR = {
    "id": "cat-okta", "name": "Okta Push Connector", "type": "PUSH", "parsers": ["okta-sso"],
    "vendor_name": "Okta", "vendor_product_name": "SSO", "log_sources": [],
}
S3_CONNECTOR = {
    "id": "cat-s3", "name": "Amazon S3 Access Log Data Connector", "type": "PULL", "parsers": ["aws-s3"],
    "vendor_name": "AWS", "vendor_product_name": "S3", "log_sources": [],
}


def _connection(id_, name, parser, source_type, vendor, product):
    return {
        "id": id_, "name": name, "parser_name": parser, "source_type": source_type, "status": "Active",
        "vendor_name": vendor, "vendor_product_name": product, "sub_connections": [],
    }


class MockFalcon:
    """Knobs are plain attributes so tests can script each failure."""

    TOKEN = "SECRET-INGEST-TOKEN-123"

    def __init__(self, port=9000):
        self.port = port
        self.connections = [
            _connection("conn-okta", "Okta prod", "okta-sso", "Push", "Okta", "SSO"),
            _connection("conn-app", "App logs", "custom-app", "Push", "Acme", "App"),
            _connection("conn-s3", "S3 access logs", "aws-s3", "Pull", "AWS", "S3"),
        ]
        self.catalog = [HEC_CONNECTOR, OKTA_CONNECTOR, S3_CONNECTOR]
        self.created = []
        self.ingested = []
        self.calls = []
        self.not_ready_polls = 1
        self.token_get_status = 200
        self.create_status = 201
        self.delete_statuses = []  # Consumed per DELETE; 200 once empty.
        self.delete_error_in_body = False
        self.token_get_non_json = False
        self.rename_clones = False  # Stores clones under a different name than was requested.
        self.hide_clones_on_read = False  # Reading a clone by ID answers 404.
        self.clone_parser_override = None  # Stores clones with this parser instead of the requested one.
        self.delete_attempts = []  # Every ID a DELETE call named, whatever its outcome.
        self.ingest_statuses = []  # Consumed per POST; 200 once empty.
        self.ingest_body = {"text": "Success", "code": 0}
        self.page_size_override = None
        self.app = self._build()

    def _build(self):
        app = Flask("mock_falcon")

        def authorized():
            return request.headers.get("Authorization") == "Bearer mock-access-token"

        @app.before_request
        def track():
            self.calls.append((request.method, request.path))
            if request.path.startswith("/ngsiem") and not authorized():
                return jsonify(errors=[{"code": 401, "message": "access denied"}]), 401

        @app.post("/oauth2/token")
        def oauth():
            if not request.form.get("client_id") or not request.form.get("client_secret"):
                return jsonify(errors=[{"code": 400, "message": "bad credentials"}]), 400
            return jsonify(access_token="mock-access-token", expires_in=1799), 201

        def page(items):
            offset = int(request.args.get("offset", 0))
            limit = self.page_size_override or int(request.args.get("limit", 100))
            return jsonify(
                resources=items[offset:offset + limit],
                meta={"pagination": {"total": len(items), "offset": offset, "limit": limit}},
            )

        @app.get("/ngsiem/combined/connections/v1")
        def list_connections():
            return page(self.connections)

        @app.get("/ngsiem/combined/connectors/v1")
        def list_connectors():
            return page(self.catalog)

        @app.get("/ngsiem/entities/connections/v1")
        def get_connection():
            found = [c for c in self.connections if c["id"] == request.args.get("ids")]
            if self.hide_clones_on_read and request.args.get("ids", "").startswith("clone-"):
                found = []
            if not found:
                return jsonify(errors=[{"code": 404, "message": "connection not found"}]), 404
            return jsonify(resources=found)

        @app.post("/ngsiem/entities/connections/v1")
        def create_connection():
            if self.create_status >= 400:
                return jsonify(errors=[{"code": self.create_status, "message": "create rejected"}]), self.create_status
            body = request.get_json()
            self.created.append(body)
            id_ = f"clone-{len(self.created)}"
            self.connections.append(_connection(
                # Falcon keeps only the first 50 characters of a name, without any error.
                id_, f"{body['name']}-renamed" if self.rename_clones else body["name"][:50],
                self.clone_parser_override or body["parser"], "Push",
                body.get("vendor_name", "Generic"), body.get("vendor_product_name", "HEC"),
            ))
            return jsonify(resources=[{"id": id_}]), 201

        @app.delete("/ngsiem/entities/connections/v1")
        def delete_connection():
            self.delete_attempts.append(request.args.get("ids"))
            status = self.delete_statuses.pop(0) if self.delete_statuses else 200
            if status != 200:
                return jsonify(errors=[{"code": status, "message": "delete rejected"}]), status
            if self.delete_error_in_body:
                return jsonify(errors=[{"code": 500, "message": "delete rejected"}])
            self.connections = [c for c in self.connections if c["id"] != request.args.get("ids")]
            return jsonify(resources=[{"id": request.args.get("ids")}])

        def token_response():
            if self.not_ready_polls > 0:
                self.not_ready_polls -= 1
                return jsonify(error="ConnectionNotReady", message="still provisioning"), 202
            return jsonify(resources={
                "token": self.TOKEN,
                "ingest_url": f"http://127.0.0.1:{self.port}/services/collector",
                "created_at": "2026-11-01T00:00:00Z",
                "expires_at": "2027-11-01T00:00:00Z",
            })

        @app.get("/ngsiem/entities/connections/token/v1")
        def get_token():
            if self.token_get_non_json:
                return "<html>gateway page</html>", 200
            if self.token_get_status != 200:
                return jsonify(errors=[{"code": self.token_get_status, "message": "token unavailable"}]), self.token_get_status
            return token_response()

        @app.post("/ngsiem/entities/connections/token/v1")
        def regenerate_token():
            return token_response()

        @app.post("/services/collector")
        @app.post("/services/collector/raw")
        def ingest():
            if request.headers.get("Authorization") != f"Bearer {self.TOKEN}":
                return jsonify(text="Invalid token", code=4), 401
            status = self.ingest_statuses.pop(0) if self.ingest_statuses else 200
            self.ingested.append({
                "path": request.path,
                "body": request.get_data(as_text=True),
                "content_type": request.content_type,
                "status": status,
            })
            if status != 200:
                return jsonify(text=f"Echoed {self.TOKEN}", code=9), status
            return jsonify(self.ingest_body)

        return app


if __name__ == "__main__":
    mock = MockFalcon()
    mock.app.run(host="127.0.0.1", port=mock.port, threaded=True)
