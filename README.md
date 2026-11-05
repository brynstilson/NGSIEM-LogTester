# NG-SIEM Log Tester

A local web app that sends a raw JSON log through a clone of an NG-SIEM data connector, so a
connector's parser can be exercised without touching the original connector.

## Setup

You need Python (tested on 3.14) and a Falcon API client with the **NGSIEM Data Connections API**
scope, Read and Write. The client gives you a client ID and a client secret, and the app needs both.

On Windows:

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
```

On macOS or Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`: set `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, and `FALCON_BASE_URL` for your cloud.
Keep this file private. Then start the app and open http://127.0.0.1:5000.

```bash
.venv\Scripts\python.exe app.py
```

On macOS or Linux, use `.venv/bin/python app.py`. Set `PORT` in `.env` to use a different port.

## Code layout

| File | Purpose |
| --- | --- |
| `app.py` | Web routes, and opening and closing forensic records |
| `workflow.py` | Clone, get credentials, send the log, delete the clone. Timeouts and retries are in `Settings` |
| `sample_events.py` | The built-in synthetic sample events |
| `falcon_client.py` | Falcon API calls and the masked verbose log |
| `forensic_log.py` | The append-only log on disk |
| `templates/index.html` | The operator page |
| `tests/` | Tests, the mock Falcon API, and the sample log generator |

To try the page without a tenant, run `python tests/mock_falcon.py` in one terminal. Then set
`FALCON_BASE_URL=http://127.0.0.1:9000`, any client ID and secret, and a separate
`FORENSIC_LOG_PATH` in `.env`, so that mock runs stay out of your real forensic log.

The app has no login and acts with the API client's rights, so it only listens on localhost. Put
real authentication in front of it before sharing it with other operators.

## What it does

1. **Lists connectors.** `GET /ngsiem/combined/connections/v1`, in PUSH and PULL sections.
2. **Reads the parser on selection.** `GET /ngsiem/entities/connections/v1`, reading `parser_name`.
   The result is kept in server memory for step 4. Pull connectors are read again at submit.
3. **Takes a raw log.** One JSON object, or an array of objects to send several events. Raw mode
   also accepts plain text, such as a syslog line.
4. **Clones and sends on submit:**
   - Falcon has no clone call, so a clone is a new connection with the same parser and vendor
     details: `POST /ngsiem/entities/connections/v1`, named `<source>-clone-<UTC timestamp>`. Falcon
     keeps only the first 50 characters of a name, so long source names are shortened to fit.
   - `GET /ngsiem/entities/connections/token/v1` returns the token and ingest URL, waiting through
     202 responses while the clone provisions. If it doesn't return a token, the app generates one
     with a `POST` to the same route.
   - The app waits 5 seconds, because a new token can briefly be rejected with HTTP 401. Change
     `ingest_ready_wait_seconds` in `workflow.py` to adjust this.
   - The log is POSTed to the ingest URL with `Authorization: Bearer <token>`. A rejected send is
     tried up to six times in total, 5 seconds apart, because some new tokens took longer than
     15 seconds to become active in live testing.
5. **Deletes the clone.** `DELETE /ngsiem/entities/connections/v1`, retried up to three times. This
   runs whether or not the log was sent, and passes through the delete limiter below.
6. **Reports success or failure**, with an expandable log of every step and HTTP exchange.
   Credentials and tokens are masked in that log. A submission counts as failed if its clone
   couldn't be deleted, and the message names the clone to remove by hand.

## Built-in sample events

The "Built-in sample event" dropdown fills the log window with a synthetic event for one of 20 log
sources. Timestamps are set when you select a sample, so reselect it if it has been sitting a while.
Every event contains `NGSIEM-LogTester-TEST`, so this finds them in Advanced Event Search:

```
"NGSIEM-LogTester-TEST"
```

They use reserved addresses and contain no real people or patient data. The events are in
`sample_events.py`, and each one is labelled with how far to trust its format:

| Label | Meaning | Sources |
| --- | --- | --- |
| Documented | Field names come from the vendor's own reference or example | Proofpoint TAP, AWS CloudTrail, AWS SecurityHub, Cloudflare, Google Workspace, Snowflake |
| Partly documented | Some field names are confirmed; the rest follow a third-party example or the commonly seen format | Windows, Entra, Cisco Firepower, vSphere, Abnormal Security, Claroty xDome, Fortinet, Okta, Palo Alto NGFW, Palo Alto Prisma |
| Approximate | No usable reference could be read, so check it against a real log | Cisco UCS, Check Point, Epic, Netskope |

**A sample isn't guaranteed to parse.** It was written from public documentation, not captured from
a product or checked against CrowdStrike's parsers. A real export may also wrap or batch events.

**Parsers:** Falcon rejects a clone whose parser name it doesn't recognize. In live testing, the
tenant's connector catalog had no parser for Cisco UCS, Abnormal Security, Netskope or Snowflake, and
the likely names `cisco-ucs`, `abnormal-security`, `netskope` and `snowflake` were rejected. Those
samples can only be sent through a connector that uses a parser your tenant has.

**Syslog sources:** Cisco UCS, Cisco Firepower and Epic natively send syslog text, so their samples
are bare lines. Selecting one switches the send mode to Raw.

## Pull connectors

A pull connector has no ingest URL, so its clone is a push connection built from the generic HEC
connector in the catalog, using the pull connector's exact parser. The pull connector, its vendor
credentials and its config aren't touched or copied. The app:

1. Reads the pull connector's current parser and records it as `source_parser_stored`.
2. Finds the one push connector in the catalog named like HEC or HTTP Event. With none or several,
   it stops before cloning and lists the candidates.
3. Creates the clone, then gets its ingest token and URL.
4. Reads the clone back and confirms its parser matches exactly. If not, nothing is sent.
5. Sends the log, then deletes the clone through the delete limiter below.

**This tests the parser, not the vendor pull.** A real pull may batch, split or wrap events before
they reach the parser, so paste the log in the shape the parser would receive it.

## Delete limiter

The app can only delete clones it created while running. `FalconClient.delete_connection`, its only
delete call, checks each delete before it reaches Falcon:

1. The ID must be on the in-memory list of clones this run created. Any other ID is refused.
2. The connector is read first, and its name must exactly match the name given to the clone. If the
   name differs, the delete is refused. If the read fails, nothing is deleted and the app retries.
3. An ID comes off the list once deleted, so it can't be deleted twice.

A refused delete isn't retried. It fails the submission, names the connector, and adds a
`clone_delete_refused` record to the forensic log.

**Limits:**

- The limiter only controls this app. The API scope allows deleting any connector, so anyone with
  the client secret can still do that outside the app. Keep `.env` private, use a dedicated API client,
  and rotate the secret if it may have been exposed.
- Anyone who can edit the source can remove the limiter, so restrict who can change the installed copy.
- After a crash or restart the list is empty, so the app can't delete a clone left behind. Remove
  it by hand. The forensic log shows it as a `clone_created` with no `clone_deleted`.

## Forensic log

Every submission is appended to `logs/forensic.jsonl` in the application directory, including
rejected input. The app only appends to this file and never rotates or deletes it. Set
`FORENSIC_LOG_PATH` to store it somewhere else.

See [samples/forensic-log-sample.jsonl](samples/forensic-log-sample.jsonl) for an example, generated
against the mock API. Each line is one JSON record, and a `submission_id` links the records of one
submission:

| Event | Contents |
| --- | --- |
| `submission_started` | OS user, client address, API client ID, Falcon URL, connector ID, send mode, built-in sample ID if unedited, the full submitted log and its SHA-256 |
| `source_parser_stored` | Pull connectors only: the source connector ID and its parser |
| `clone_created` | Clone ID, name, parser, source type, and the catalog connector it was built from |
| `clone_delete_refused` | Clone details and why the delete limiter refused. Followed by `clone_delete_failed` |
| `clone_deleted` or `clone_delete_failed` | Clone details, and the error if it failed |
| `submission_finished` | Outcome, message, source connector, clone, and the verbose log |

- Records are flushed to disk as they happen, so a crash still leaves a trail of any clone it
  stranded. A `clone_created` with no matching `clone_deleted` is a clone to check for.
- If `submission_started` can't be written, the submission stops before anything changes in the tenant.
- Tokens and credentials are masked, but **submitted logs are stored in full and in plain text**.
  Restrict access to this file if your logs can contain sensitive data.
- Log entries over 20,000 characters are truncated in the verbose log. `submitted_log` never is.
- The file is append-only by convention, not tamper-proof. Anyone with write access can edit it.

## Behavior to know about

- **The source connector is inferred.** The API doesn't return `connector_id` when reading a
  connection, and creating one requires it. The app looks in the connector catalog for one push
  connector that matches, trying vendor and product, then parser, then the generic HEC connector.
  If it can't narrow that to one, it stops before cloning and lists the candidates in the message.
- **Enrichment isn't copied.** The API doesn't return a connection's enrichment settings, so clones
  use host and user enrichment on, the same as the console default. Change `enable_enrichment` in
  `workflow.py` to turn it off.
- **The clone is deleted right after the POST.** The app doesn't wait for the log to finish processing.
- **Tokens are used once and discarded.** They are never stored or displayed.
- **Success means the ingest endpoint accepted the log.** It doesn't confirm the parser produced the
  fields you expected. Check that in Advanced Event Search.

## Send modes

| Mode | Target | Body |
| --- | --- | --- |
| HEC event (default) | The ingest URL as returned | `{"event": <your log>}`. JSON only |
| Raw | The ingest URL plus `/raw` | Your log, unchanged. JSON or plain text |

In Raw mode, anything that isn't a JSON object or array of objects is sent as plain text, including
JSON with a typo. The page warns you when this will happen, and the verbose log records it.

## Tests

The tests run against `tests/mock_falcon.py`, a stand-in built from CrowdStrike's published API
models. They don't contact a real tenant.

```bash
.venv\Scripts\python.exe -m pytest tests
```
