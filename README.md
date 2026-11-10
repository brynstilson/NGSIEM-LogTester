# NG-SIEM Log Tester

A local web app that sends a raw JSON log through a clone of an NG-SIEM data connector, so a
connector's parser can be exercised without touching the original connector. It also estimates
whether a log will trigger your correlation rules, and warns before sending one that probably will.

## Setup

You need Python (tested on 3.14) and a Falcon API client. The client gives you a client ID and a
client secret, and the app needs both. Give it these scopes:

| Scope | Access | Used for |
| --- | --- | --- |
| NGSIEM Data Connections | Read and Write | Listing connectors, reading parsers, creating and deleting clones, ingest tokens |
| Correlation Rules | Read | Reading configured rules and CrowdStrike's rule templates |

Correlation Rules Write isn't needed. Without the Correlation Rules scope, the app still sends logs,
but it can't check them against rules.

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

## Application settings

The **Settings** button at the top of the page lets an administrator set a header title, a company
logo, and contact details (name, email, phone and a note) shown at the bottom of the page. Changes
apply to everyone using the installation.

- **Who can change them:** by default, anyone who can open the page. To limit changes to
  administrators, set `APP_ADMIN_PASSWORD` in `.env` and restart the app. The dialog then asks for it.
- **Logo:** PNG, JPEG, GIF or WebP, up to 1 MB. SVG isn't accepted, because it can carry script.
- **Where they're stored:** `app_settings.json` and the `branding/` folder in the application directory.
  Both are left out of Git, so each installation keeps its own. Set `APP_SETTINGS_PATH` and
  `APP_BRANDING_DIR` to store them elsewhere.
- **Audit trail:** each change is recorded in the forensic log as `settings_changed`. Logos are
  recorded by size and SHA-256, not stored in the log.

## Code layout

| File | Purpose |
| --- | --- |
| `app.py` | Web routes, and opening and closing forensic records |
| `workflow.py` | Clone, get credentials, send the log, delete the clone. Timeouts and retries are in `Settings` |
| `sample_events.py` | The built-in synthetic sample events |
| `rules.py` | Loading correlation rules, judging a submission against them, and building rule templates |
| `cql.py` | Reading a rule's CQL query and evaluating its filter against one event |
| `field_model.py` | What each parser gives a rule: tags, `Vendor.` fields, ECS mappings and text-format readers |
| `falcon_client.py` | Falcon API calls and the masked verbose log |
| `forensic_log.py` | The append-only log on disk |
| `app_settings.py` | Administrator settings: title, logo and contact details |
| `templates/index.html` | The operator page |
| `tests/` | Tests, the mock Falcon API, and the sample log generator |

To try the page without a tenant, run `python tests/mock_falcon.py` in one terminal. Then set
`FALCON_BASE_URL=http://127.0.0.1:9000`, any client ID and secret, and a separate
`FORENSIC_LOG_PATH` in `.env`, so that mock runs stay out of your real forensic log.

### Running on a server (client/server)

The app acts with the API client's rights, so by default it only listens on localhost
(`HOST=127.0.0.1`). To reach it from another machine, choose one of these:

- **SSH tunnel (no change needed).** From the workstation, run
  `ssh -L 5000:127.0.0.1:5000 user@server`, then browse to http://127.0.0.1:5000.
- **Listen on the network.** In the server's `.env`, set all of these, then restart the app:

  | Setting | Value |
  |---|---|
  | `HOST` | `0.0.0.0` |
  | `APP_ACCESS_PASSWORD` | The password every operator signs in with |
  | `APP_ADMIN_PASSWORD` | A different password, for changing the settings |
  | `APP_ALLOWED_HOSTS` | The address people browse to, such as `10.0.0.5` or `logtester.corp.example` |

  The app refuses to start if any of them is missing. Browse to `http://<server-address>:5000`;
  the browser asks for a user name and password. Any user name works, and it is recorded in the
  forensic log as `operator_login`. Open the port in the server's firewall, only for the
  workstations that need it. For example:
  `sudo ufw allow from <workstation-ip> to any port 5000 proto tcp`, or
  `sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address=<workstation-ip> port port=5000 protocol=tcp accept' --permanent`
  followed by `sudo firewall-cmd --reload`.

  Traffic is plain HTTP, so passwords cross the network unencrypted. Use this only on a trusted
  network for testing.

**Access protections:**
- **Host check:** requests addressed to any host name other than localhost, 127.0.0.1 or
  `APP_ALLOWED_HOSTS` get HTTP 421. This blocks DNS rebinding, where a malicious web page poses as
  the app in an operator's browser.
- **Lockout:** 5 wrong operator or administrator passwords from one address within 5 minutes lock
  that address out for 5 minutes (HTTP 429). Restarting the app clears lockouts. Behind a reverse
  proxy every user shares the proxy's address, so one person's mistakes can lock everyone out.
- **Checks before recording:** a submission must name a connector that exists, a valid send mode
  and a non-empty log before anything is written to the forensic log.
- **Falcon API limits:** each address may make 30 requests a minute to the routes that call the
  Falcon API (connectors, connector details, rules, templates and submit). Further requests get HTTP
  429 with a `Retry-After` header. Connector details are only read for IDs from the latest connector
  listing; an unknown ID triggers at most one new listing every 30 seconds, so made-up IDs can't
  drive Falcon API calls or grow the app's cache.
- **Browser headers:** the page has a strict Content-Security-Policy (only its own script and style,
  marked with a per-request nonce, may run). Every response tells the browser not to frame the
  page, not to guess content types, and not to send a referrer. The `Server` header no longer
  reveals the Werkzeug or Python version.

Before sharing the app with other operators permanently, put real authentication and HTTPS in front
of it, for example a reverse proxy with single sign-on.

## What it does

1. **Lists connectors.** `GET /ngsiem/combined/connections/v1`, in PUSH and PULL sections.
2. **Reads the parser on selection.** `GET /ngsiem/entities/connections/v1`, reading `parser_name`.
   The result is kept in server memory for step 4. Pull connectors are read again at submit.
3. **Takes a raw log.** One JSON object, or an array of objects to send several events. Raw mode
   also accepts plain text, such as a syslog line. As you edit, the page estimates which
   correlation rules the log would trigger. See [Correlation rules](#correlation-rules).
4. **Checks correlation rules on submit.** If the log will probably trigger an enabled rule in your
   tenant, the app stops before cloning anything and asks you to acknowledge those rules.
5. **Clones and sends:**
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
6. **Deletes the clone.** `DELETE /ngsiem/entities/connections/v1`, retried up to three times. This
   runs whether or not the log was sent, and passes through the delete limiter below.
7. **Reports success or failure**, with an expandable log of every step and HTTP exchange.
   Credentials and tokens are masked in that log. A submission counts as failed if its clone
   couldn't be deleted, and the message names the clone to remove by hand.

## Built-in sample events

The "Built-in sample event" dropdown fills the log window with a synthetic event. Its first group,
"Vendor sample logs", has one event for each of 20 log sources. The groups after it are logs built
to match correlation rules (see [Correlation rules](#correlation-rules)). Timestamps are set when
you select a sample, so reselect it if it has been sitting a while.
Every event contains `NGSIEM-LogTester-TEST`, so this finds them in Advanced Event Search:

```
"NGSIEM-LogTester-TEST"
```

They use reserved addresses and contain no real people or patient data. The events are in
`sample_events.py`, and each one is labelled with how far to trust its format:

| Label | Meaning | Sources |
| --- | --- | --- |
| Documented | Field names come from the vendor's own reference or example | Proofpoint TAP, Windows, AWS CloudTrail, AWS SecurityHub, Cloudflare, Fortinet, Google Workspace, Palo Alto NGFW, Snowflake |
| Partly documented | Some field names are confirmed; the rest follow a third-party example or the commonly seen format | Entra, Cisco Firepower, vSphere, Abnormal Security, Claroty xDome, Epic, Okta, Palo Alto Prisma |
| Approximate | No usable reference could be read, so check it against a real log | Cisco UCS, Check Point, Netskope |

### Matched to CrowdStrike's parsers

Each sample is shaped for the CrowdStrike parser that handles its source. Its note names that parser,
and so does the `parser` entry in `sample_events.py`. The samples were compared with the 318 parsers
in the tenant on 9 November 2026, using each parser's own logic: how it recognizes its input, which
field holds its timestamp, and which fields set `event.action`. The parsers include no example events,
so this is a check against their logic, not a test run through them.

| Source | Parser | Format the parser expects |
| --- | --- | --- |
| Proofpoint TAP | `proofpoint-tap` | One message per event, with `eventType` (such as `messagesDelivered`), which sets `event.action` |
| Windows | `microsoft-windows` | Native Windows event XML (Raw mode) |
| Entra | `microsoft-entra-id` | Azure Monitor sign-in record |
| Cisco Firepower | `cisco-firepower` | `%FTD` syslog line (Raw mode) |
| vSphere | `vmware-vcenter` | vCenter `vpxd` syslog with its bracketed `Event [...]` format (Raw mode) |
| AWS CloudTrail | `aws-cloudtrail` | CloudTrail record |
| AWS SecurityHub | `aws-security-hub` | Finding in AWS Security Finding Format |
| Abnormal Security | `abnormal-emailsecurity` | Threat message |
| Check Point | `checkpoint-ngfw` | Log Exporter JSON |
| Claroty xDome | `claroty-xdome` | Alert event with `alert_id`, `event_id` and device fields |
| Cloudflare | `cloudflare-waf` | Firewall events record, with `Datetime` and `Action` |
| Epic | `epic-ehr` | Syslog carrying Epic's `EventLog` XML and `Mnemonics` (Raw mode) |
| Fortinet | `fortinet-fortigate` | key=value syslog (Raw mode). The parser has no JSON input |
| Google Workspace | `google-workspace` | Admin Reports activity |
| Netskope | `netskope-sse` | REST API event |
| Okta | `okta-sso` | System Log event |
| Palo Alto NGFW | `paloalto-ngfw` | PAN-OS positional CSV traffic log (Raw mode) |
| Palo Alto Prisma | `paloalto-prisma-access` | GlobalProtect log with `LogType`, `EventName`, `SourceUser` and `SourceAddress` |
| Snowflake | `snowflake-audit` | `LOGIN_HISTORY` row |
| Cisco UCS | None | No CrowdStrike parser is available, so NG-SIEM won't parse it |

**A sample still isn't guaranteed to parse.** The comparison was with the parsers' logic, and parsers
are updated. To check a sample, send it and look at the parsed fields in Advanced Event Search.

**Parser names:** Falcon rejects a clone whose parser name it doesn't recognize. A sample can only be
sent through a connector that uses a parser your tenant has.

**Text formats:** samples for sources that send text (Windows, Cisco UCS, Cisco Firepower, vSphere,
Epic, Fortinet and Palo Alto NGFW) are in their native format. Selecting one switches the send mode
to Raw.

## Correlation rules

The app reads your tenant's configured correlation rules
(`GET /correlation-rules/combined/rules/v1`) and CrowdStrike's built-in rule templates
(`/correlation-rules/queries/templates/v1` and `/correlation-rules/entities/templates/v1`). This needs
the **Correlation Rules: Read** scope. Without it, the app still sends logs, but the page shows that
rules couldn't be checked, and the forensic log records that the submission wasn't screened.

**Configured rules by default, templates on request:** the app loads only the rules configured in
your tenant, which takes one API call. CrowdStrike's templates can run to well over 1,000, need many
calls and can take 15 seconds or more, so they load only when you choose **Load samples for
CrowdStrike rule templates** under the sample dropdown. Once loaded, template samples join the dropdown
and the live check, and the same button hides them again. Submitting never loads the templates, because
templates can't fire.

Rules are cached for 15 minutes. After changing rules in Falcon, use **Reload rules** in the rule
check panel under the log window.

### Rule templates in the dropdown

For each rule a third-party log could trigger, the dropdown has a generated log:

- **Grouped by vendor and product,** such as "Okta / Okta SSO". Templates that span several vendors
  are grouped by their vendor list, as "Multiple sources".
- **Labelled by source:** configured, configured but not enabled, or CrowdStrike template. A template
  that one of your configured rules was created from is listed once, as the configured rule.
- **Built from the vendor's sample event,** changed to meet the rule's conditions. A rule that needs
  several events gets enough of them. Key=value text, such as Fortinet's, is edited field by field.
  Other text formats, such as XML or CSV, are left as they are, and the note under the dropdown says
  what to change.
- **Rules over Falcon sensor data get no template,** because no third-party log can trigger them.

All the page's dropdowns open a scrollable, left-aligned list in which long names wrap rather than
being cut off. The sample list also has a filter box, which matches option and group names.

The note under the dropdown names the rule a template was built for and gives the check's verdict.

### Live check

As you edit the log, change the send mode or pick a connector, the panel under the log window
estimates which rules the submission would match. Each rule shows one of these verdicts:

| Verdict | Meaning |
| --- | --- |
| Likely to match | Every checkable condition is met, including at least one on the log's own fields |
| Needs more events | Matching events were found, but the rule needs more of them |
| Can't fully check | Some conditions depend on the parser, or the query uses something the app doesn't evaluate |
| Unlikely to match | At least one condition isn't met |
| Not applicable | The rule runs on Falcon sensor data |

The badge summarizes the result: whether enabled rules will probably fire, whether templates would
match if enabled, or whether nothing is likely to trigger. The panel lists likely matches, rules
needing more events, your configured rules that can't be fully checked, and the selected template's
own rule. Other templates that can't be fully checked are only counted, so they don't flood the list.

Each listed rule expands to show its conditions, what the log has, and what each check was based on.
Suggestions name the raw field to add or change, catch case mismatches and near-miss field names,
and say how many events are still needed. When a rule has `case` branches, suggestions follow the
branch closest to passing.

**Which parser is assumed:** the selected connector's parser. With no connector selected, the
parser the selected sample or template was written for is used instead.

### Acknowledgement

If the submission will probably trigger an enabled configured rule, the app stops before cloning
anything and shows those rules in a dialog, grouped by vendor and product, each expandable. Nothing is
sent until you tick the acknowledgement and choose Proceed. Cancel sends nothing. The server enforces
this too, so a submission that doesn't acknowledge every such rule is refused.

The forensic log records the check and the rules you acknowledged. CrowdStrike templates and rules
that aren't enabled never fire, so they don't need acknowledgement.

### Limits of the check

**This is an estimate, not NG-SIEM's evaluation.** Rules match on fields the parser produces, such as
`#Vendor`, `event.action` and `Vendor.*`, and the app only sees the raw log. Following CrowdStrike's
parsing standard, it assumes raw fields appear under a `Vendor.` prefix. It takes `#Vendor` from the
connector's parser, and assumes standard values for tags such as `#event.kind`. Its mappings for
common ECS fields such as `event.action`, and the way it reads text formats such as Windows XML,
vCenter `Event [...]` lines and Palo Alto CSV, follow the logic of the tenant's parsers as read on
9 November 2026 (see `field_model.py`). Parsers are updated, so these can drift.

- **Understood:** comparisons, regexes, wildcards, `in()`, `cidr()`, `case { }` branches,
  `array:contains()`, and event-count thresholds after an aggregation.
- **Not evaluated:** `correlate()`, `join()`, `defineTable()`, `match()`, lookups and `test()`.
  Fields only the parser creates show as unknown rather than guessed.
- **A match on parser tags alone,** such as `#Vendor`, is reported as "can't fully check", because it
  says nothing about the log.
- **The lookback window isn't considered,** so earlier events in the tenant may still count toward a
  threshold.
- **Coverage in practice:** in live testing against 1,628 rules, 253 needed Falcon sensor data, and
  most of the rest could only be judged "can't fully check". Treat "Unlikely" and "Can't fully check"
  as estimates, not guarantees.

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
| `submission_started` | OS user, client address, API client ID, Falcon URL, connector ID, send mode, the sample or rule template ID if unedited, the correlation rule check (checked or unavailable, how many rules, and the rules you acknowledged), the full submitted log and its SHA-256 |
| `source_parser_stored` | Pull connectors only: the source connector ID and its parser |
| `clone_created` | Clone ID, name, parser, source type, and the catalog connector it was built from |
| `clone_delete_refused` | Clone details and why the delete limiter refused. Followed by `clone_delete_failed` |
| `clone_deleted` or `clone_delete_failed` | Clone details, and the error if it failed |
| `submission_finished` | Outcome, message, source connector, clone, and the verbose log |
| `settings_changed` | OS user, client address, and the settings that changed. A new logo is recorded by file type, size and SHA-256 |

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
