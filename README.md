# Zenith AI SecOps Platform

An offline-first security operations demo for ingesting events, preserving their original submissions, explaining data-quality findings, grouping evidence-linked events, and producing a shift briefing. The local application runs on a CPU-only laptop without a GPU, paid API key, or cloud service.

## Technology stack

- **Language:** Python 3.10+
- **Database:** SQLite with WAL mode and indexed event, quality, and incident records
- **Frontend:** plain HTML, CSS, and browser JavaScript; no frontend framework or build step
- **AI / reasoning:** no paid model and no GPU. Correlation, briefing, and the operator assistant use deterministic, documented rules so evidence links stay repeatable and work offline. Optional browser speech recognition depends on the browser and may require connectivity; text is the offline path.
- **Mobile app:** installable Progressive Web App (PWA) using the same local API and database. It supports an app icon, standalone display, touch-sized controls, and cached read-only snapshots for previously viewed data.
- **Cloud provider:** none; the application and database run locally.

## AI tools used

The application runtime does not call a language model or external AI service. OpenAI Codex was used to help implement and review this assessment project. The deterministic fallback is the normal runtime path, not a degraded mode.

## Project layout and architecture

```text
app/                 Python API, browser UI, PWA manifest, icons, and service worker
data/sample_events.jsonl  Small reproducible walkthrough dataset
data/secops.db       Persistent SQLite database created on first start (ignored by Git)
tools/seed.py        Loads the walkthrough events into the running app
tools/generate.py    Reproducible clean or adversarial JSONL generator
tests/               Isolated API, data-quality, correlation, and 50k-event tests
run.ps1              Windows startup
run-public.ps1       Temporary authenticated HTTPS demo tunnel
test.ps1             Windows one-command test runner
Makefile             Cross-platform `make test` target
Dockerfile           Optional container setup with persistent data volume
```

The browser UI sends JSON to the standard-library `ThreadingHTTPServer`. The API validates each submission, writes the exact original to the intake audit and canonical SQLite tables, and rebuilds deterministic quality and incident views. The briefing and assistant read those stored records and return source event IDs with their explanations. SQLite uses WAL mode and indexes. By default the database is `data/secops.db`; `SECOPS_DB` can point it to another persistent path.

### Design decisions and trade-offs

- Python's standard library and SQLite avoid package installation, paid services, GPUs, and network dependencies. This keeps laptop setup small; it is a single-machine demo rather than a high-availability service.
- Original submissions and canonical events are stored separately from quality flags and incident links. This costs disk space but keeps duplicates, conflicts, and malformed intake auditable.
- Correlation requires explicit shared identity evidence plus compatible time and location. This avoids proximity-only false links; events with missing identity may remain uncorrelated.
- Rules-based reasoning keeps results repeatable and evidence-grounded offline. It is easier to audit but less flexible than a domain-tuned language model.
- The PWA uses plain browser files with no build pipeline. It installs from an HTTPS origin; it is not a separately packaged Play Store APK.

## Setup and run

### Prerequisites

Install Python 3.10 or newer. The app uses only the Python standard library, so no `pip install` step is required. Docker is optional.

### Start the app

From the project root on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

The Windows launcher uses Python from `PATH`; this development environment also has a bundled Python fallback. On macOS or Linux, run:

```sh
python3 app/server.py
```

Open <http://127.0.0.1:8000>. The server creates the SQLite database at `data/secops.db` on first start. Keep the terminal open while using the app and press `Ctrl+C` to stop it. Set `PORT` or `SECOPS_DB` before startup to change the port or database path.

### Load the walkthrough data

In a second terminal, from the project root, run:

```powershell
python tools/seed.py
```

Or on macOS/Linux:

```sh
python3 tools/seed.py
```

The seven curated events demonstrate cross-source vehicle evidence, a delayed low-confidence observation, a device-health alert, and an event with incomplete location. Re-running the seed preserves existing rows and records repeated submissions.

### Share a protected HTTPS demo

For phone access outside the computer's local network, install the official Cloudflare Tunnel client and start the protected temporary tunnel:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\install_cloudflared.ps1
powershell -ExecutionPolicy Bypass -File .\run-public.ps1
```

The tunnel script asks for a login name and a password of at least 16 characters. It binds the app server to localhost and prints a temporary HTTPS URL. The small web-app shell, manifest, icons, and service worker are public so Chrome can inspect them for installation; event, incident, briefing, health, and other operational API data require the login form. Credentials stay in the current browser tab's session storage. Optionally pass `-AllowedEmail you@example.com` to require Cloudflare's email one-time PIN as an additional gate. Keep the computer, app, and tunnel window running while using the link; press `Ctrl+C` to close access. Quick Tunnel URLs change when restarted and have no uptime guarantee; for a permanent URL, use a named Cloudflare Tunnel and a domain. See [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) and [Cloudflare downloads](https://developers.cloudflare.com/tunnel/downloads/).

Optional Docker run, with SQLite persisted in a named volume:

```sh
docker build -t zenith-secops .
docker run --rm -p 8000:8000 -v zenith-data:/app/data zenith-secops
```

Open <http://127.0.0.1:8000>.

### Install on a phone or tablet

Open the app from an HTTPS URL in a supported mobile browser, then choose **Install app** or **Add to Home Screen** from the browser menu. On iPhone/iPad, use Safari's Share menu and select **Add to Home Screen**. The PWA uses the same backend as the desktop UI; the server must be reachable by the phone. Service-worker installation requires HTTPS (or localhost on the same device). The app shell and previously viewed read-only pages can be opened offline; ingest and incident updates require the server connection.

## Generate sample data

Create a reproducible 50,000-event JSONL dataset locally:

```powershell
python tools/generate.py --count 50000 --seed 41 --output data/generated_50k.jsonl
```

Generated benchmark files are created locally on demand and are not checked into the source repository. The generator and small seed dataset are included.

The generated fixture includes exact duplicate submissions, malformed and incomplete records, delayed and out-of-order events, conflicting sensor observations, device failures, low-confidence detections, access-control spikes, related events, and unrelated events at the same time and place. Use `--clean` to generate only valid records without the injected quality cases.

## Event preservation and data quality

- The first event for a source ID is retained as the canonical event. Every accepted row, exact repeat, conflicting repeat, and non-object submission is also kept in `ingestion_records` with its original JSON value and disposition. A conflicting submission never overwrites the stored event.
- `event_id` is used as the source identifier; `source_id` is accepted as an alias when `event_id` is absent. The API returns `source_event_id` alongside the normalized ID. Other source fields remain in the original JSON.
- Findings cover missing or malformed fields, invalid source/severity/confidence/location/payload, exact duplicate IDs, conflicting content under a reused ID, delayed arrival, impossible timestamp order, out-of-order device events, spikes, low-confidence detections, unhealthy devices, contradictory evidence, distant observations of the same identity, and high-severity events without a usable correlation anchor.
- Events with quality problems remain stored and visible. Duplicate and conflicting-ID findings have an audit-history control in Data quality.
- Syntactically malformed `/ingest` request bodies are preserved byte-for-byte (base64 encoded in the audit record); malformed JSONL lines are retained while valid neighboring lines in the same file can still be processed. Data quality includes an audit viewer for invalid intake submissions.

## Correlation and briefings

- Cross-source correlation requires the same explicit `vehicle_id`, `plate`, or `subject_id`, plus compatible location and a 20-minute event-time window. Location and time alone do not link events.
- Repeated alerts from the same device and event type may group inside a 90-second burst. The incident view states which rule linked records, lists event IDs and shows uncertainty, low confidence, missing location, and conflicts.
- Incident responses expose `timeline`, `related_events`, `event_ids`, `source_event_ids`, `conflicts`, `missing_information`, `quality_issues`, and `next_actions` as structured fields alongside title, category, severity, confidence, status, devices, locations, and linkage basis.
- The rules sort by event time and detect out-of-order source arrivals. Late records trigger a deterministic rebuild, so arrival order does not determine incident membership.
- The shift briefing reports priorities, unresolved work, new incidents in the chosen window, activity trends, device health, quality findings, recommendations, and source event IDs. It is rule-based rather than generated by a language model.
- The Assistant tab answers natural-language operator questions over stored data (incidents, evidence, quality, briefing). Replies include `answer`, `incident_ids`, `evidence_event_ids`, `confidence`, and `requires_confirmation`. Acknowledge, assign, close, and false-positive never apply until `POST /assistant/confirm`. Text always works; hold-to-talk uses the browser when available.

## Large batches and tests

The ingest API and browser file picker accept payloads/files up to 50 MiB per request. The ingest API accepts up to 100,000 events. Larger payloads may need to be split into smaller requests.

Run the automated test suite with GNU Make:

```sh
make test
```

On Windows, use the included PowerShell command:

```powershell
powershell -ExecutionPolicy Bypass -File .\test.ps1
```

On macOS or Linux:

```sh
python -m unittest discover -s tests -v
```

The suite starts an isolated server and a unique SQLite database under the ignored `work/test-runs/` directory. Test artifacts may remain there for troubleshooting; they do not clear or alter the app's `data/secops.db` or other project data. It includes six integration tests, including ingestion and pagination of a generated 50,000-event batch.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/health` | App and canonical event count |
| GET | `/summary` | Dashboard totals |
| POST | `/ingest` | One event or an array; preserves each submission |
| GET | `/events` | Filtered, paginated source events |
| GET | `/events?event_id=...&include_raw=1` | Fetch cited source events and their original submitted JSON |
| GET | `/incidents` | Filtered, paginated incidents with evidence and linkage details |
| GET | `/incidents/{id}` | One incident with attached evidence |
| POST | `/incidents/{id}/actions` | Acknowledge, assign, close, reopen, or false_positive |
| GET | `/quality-issues` | Filtered, paginated quality findings |
| GET | `/ingest-records?event_id=...` | Raw submission history for one source ID |
| GET | `/ingest-records?disposition=invalid` | Audit records for invalid or malformed intake |
| GET | `/briefing` | Evidence-backed briefing; optional ISO-8601 `since` and `until` |
| POST | `/assistant/query` | `{ "query": "..." }` grounded operator answer |
| POST | `/assistant/confirm` | `{ "pending_id": "...", "confirmed": true }` |
| GET | `/assistant/history` | Assistant transcript |

`POST /ingest` accepts one event object or an array. Example:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/ingest `
  -ContentType 'application/json' `
  -Body '{"event_id":"example-1","source_type":"cctv","device_id":"cam-1","event_type":"person_detected","occurred_at":"2026-01-15T08:00:00Z","received_at":"2026-01-15T08:00:02Z","location":{"zone":"Gate-A"},"severity":"medium","confidence":0.82,"payload":{}}'
```

The response includes submitted, accepted, rejected, duplicate, and conflicting counts; detailed per-record results are capped at the first 500 entries. Batches are limited to 100,000 events and 50 MiB per request. `GET /events`, `/incidents`, and `/quality-issues` accept `page` and `limit` plus applicable filters (`severity`, `source`, `zone`, `device`, `since`, `until`). Their responses include a total count and page metadata. Use repeated `event_id` query parameters with `/events` to fetch cited source rows; add `include_raw=1` to include the exact original JSON. Malformed JSON on `POST /ingest` returns HTTP 400 and a `submission_id`; retrieve its preserved bytes via `/ingest-records?disposition=invalid`. Incomplete but syntactically valid event objects are accepted and flagged rather than dropped.

## Event schema

Every source uses the same envelope. `event_id` is the preferred source identifier; `source_id` is accepted as an alias. `source_type`, `device_id`, `event_type`, `occurred_at`, and `received_at` are mandatory for a complete record. Missing or malformed values produce quality findings; the submitted record is still preserved. Timestamps should be ISO-8601 with a timezone. `severity` is one of `critical`, `high`, `medium`, `low`, or `info`; `confidence` is a number from 0 to 1. `location` and `payload` may be absent, but absence can reduce correlation confidence or create a finding. Unknown source-specific fields are retained in the original record.

```json
{
  "event_id": "vendor-evt-1042",
  "source_type": "anpr",
  "device_id": "north-gate-anpr-2",
  "event_type": "vehicle_detected",
  "occurred_at": "2026-01-15T08:12:14Z",
  "received_at": "2026-01-15T08:12:16Z",
  "location": {"latitude": 25.2048, "longitude": 55.2708, "zone": "Gate-A"},
  "severity": "high",
  "confidence": 0.94,
  "payload": {"plate": "DXB123", "vehicle_id": "fleet-22"}
}
```

The `source_type` enum contains all 15 supported categories. Payload fields below are useful conventions, not restrictions; arbitrary source fields are preserved.

| `source_type` | Typical `event_type` | Common payload fields |
|---|---|---|
| `cctv` | `person_detected`, `vehicle_present`, `intrusion_alert` | `vehicle_id`, `subject_id`, `camera_channel`, `image_ref` |
| `anpr` | `vehicle_detected` | `plate`, `vehicle_id`, `plate_text` |
| `face_recognition` | `face_match` | `subject_id`, `match_id`, `match_score`, `image_ref` |
| `mobile_phone` | `mobile_phone_detected` | `subject_id`, `device_hash`, `detection_method` |
| `seatbelt` | `seatbelt_violation` | `vehicle_id`, `seatbelt_status`, `seat_position` |
| `red_light` | `red_light_violation` | `vehicle_id`, `signal_state`, `lane_id` |
| `radar` | `speed_violation`, `vehicle_detected` | `vehicle_id`, `speed_kph`, `direction` |
| `access_control` | `access_granted`, `access_denied` | `credential_id`, `door_id`, `decision` |
| `perimeter` | `intrusion_alert`, `perimeter_clear` | `zone`, `sensor_id`, `intrusion_state` |
| `device_health` | `device_offline`, `device_online` | `status`, `heartbeat_age_seconds`, `error_code` |
| `operator_report` | `suspicious_activity_report` | `report_id`, `narrative`, `reporter_id` |
| `emergency_alarm` | `alarm_raised`, `alarm_cleared` | `alarm_code`, `panel_id`, `zone` |
| `gps_fleet` | `vehicle_location`, `speed_violation` | `vehicle_id`, `speed_kph`, `heading`, `route_id` |
| `network_log` | `authentication_failure`, `connection_blocked` | `src_ip`, `username`, `action`, `session_id` |
| `weather` | `weather_alert`, `visibility_reduced` | `condition`, `visibility_m`, `wind_kph` |

## Known limits

- Local demo mode has no authentication. Public mode allows the PWA shell and installation assets anonymously, while all operational APIs require the entered HTTP Basic credentials over HTTPS. It is a demo gate, not a production role model or multi-tenant control.
- The mobile client is an installable PWA, not a separately compiled Android APK or iOS IPA. Phone access to the local server needs a reachable HTTPS address for service-worker installation.
- Cross-source identity is explicit; the demo does not infer faces or vehicle identity from video or images.
- Contradiction rules cover a documented event vocabulary. A deployed system needs domain mappings and operator adjudication.
- Large-batch processing and deterministic correlation run on one machine. SQLite is suitable for this laptop demo, not a high-availability multi-user deployment.
- Voice input depends on the browser (Chrome/Edge). If STT is missing, type the same questions.

## Demo guide (under 5 minutes)

[Watch the project walkthrough](https://drive.google.com/file/d/1xh_BDyAQEJdkuXm39rmS_Pkg8V2NoIQJ/view?usp=sharing).

Estimated total: 4–5 minutes.

1. (30 sec) Start the server, seed sample events, and open the dashboard.
2. (45 sec) Filter incidents by severity, source, location, device, or time; expand a timeline and inspect linkage plus uncertainty.
3. (60 sec) Open Data quality and show reasons for delayed, malformed, duplicate, low-confidence, or conflicting records; expand the malformed-intake audit.
4. (45 sec) Open Shift briefing and point at event ID references and management actions.
5. (90 sec) Ask the Assistant: “Show unresolved high-severity incidents near Gate-A”; expand “Show source events” to inspect original JSON, then close an incident only after confirmation.
6. (30 sec) Paste or upload a JSON event and refresh.

## Verification results

The latest Windows run passed all six automated integration tests in 29.6 seconds. It includes a 50,000-event batch ingest and API pagination check; a separate 1,000-event adversarial fixture checks known related and unrelated pairs while keeping labels outside event input. Other checks cover preservation, duplicates and conflicts, malformed input, data-quality explanations, out-of-order arrivals, assistant evidence, and confirmation-gated actions. The elapsed time is one local run, not a performance guarantee across machines. Run `make test` or `test.ps1` to reproduce the results on the current code.


