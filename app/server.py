"""Offline-first SecOps demo API and web server. Uses only Python's standard library."""
from __future__ import annotations
import base64, json, os, re, sqlite3, threading, hashlib, math, uuid, hmac
from datetime import datetime, timedelta, timezone
from bisect import bisect_left
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get('SECOPS_DB', ROOT / 'data' / 'secops.db'))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
LOCK = threading.RLock()
AUTH_USERNAME = os.environ.get('SECOPS_USERNAME', '')
AUTH_PASSWORD = os.environ.get('SECOPS_PASSWORD', '')
PUBLIC_MODE = os.environ.get('SECOPS_PUBLIC', '').lower() in ('1', 'true', 'yes')
EXPECTED_AUTH = ('Basic ' + base64.b64encode(f'{AUTH_USERNAME}:{AUTH_PASSWORD}'.encode()).decode()) if AUTH_USERNAME and AUTH_PASSWORD else ''
PUBLIC_ASSETS = {'/', '/app.js', '/style.css', '/manifest.webmanifest', '/sw.js', '/offline.html', '/app-icon.svg', '/app-icon-192.png', '/app-icon-512.png'}
SOURCES = {'cctv','anpr','face_recognition','mobile_phone','seatbelt','red_light','radar','access_control','perimeter','device_health','operator_report','emergency_alarm','gps_fleet','network_log','weather'}
SEVERITY = {'critical':4,'high':3,'medium':2,'low':1,'info':0}

def connect():
    c=sqlite3.connect(DB_PATH, timeout=30); c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA synchronous=NORMAL'); return c

def init_db():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, source_type TEXT, device_id TEXT, event_type TEXT, occurred_at TEXT, received_at TEXT, latitude REAL, longitude REAL, zone TEXT, severity TEXT, confidence REAL, payload TEXT, raw TEXT, fingerprint TEXT);
        CREATE INDEX IF NOT EXISTS event_time ON events(occurred_at); CREATE INDEX IF NOT EXISTS event_device ON events(device_id);
        CREATE TABLE IF NOT EXISTS quality(id INTEGER PRIMARY KEY, event_id TEXT, kind TEXT, severity TEXT, reason TEXT);
        CREATE INDEX IF NOT EXISTS quality_event ON quality(event_id);
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, title TEXT, category TEXT, severity TEXT, confidence REAL, status TEXT, explanation TEXT, actions TEXT, first_at TEXT, last_at TEXT, assignee TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS incident_events(incident_id TEXT, event_id TEXT, UNIQUE(incident_id,event_id));
        CREATE TABLE IF NOT EXISTS incident_state(incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, assignee TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ingestion_records(submission_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, submitted_at TEXT NOT NULL, disposition TEXT NOT NULL, raw TEXT NOT NULL, fingerprint TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS ingestion_event ON ingestion_records(event_id,submission_id);
        CREATE TABLE IF NOT EXISTS assistant_history(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, role TEXT NOT NULL, query TEXT, response TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS assistant_pending(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, incident_id TEXT, action TEXT NOT NULL, assignee TEXT NOT NULL DEFAULT '', query TEXT, status TEXT NOT NULL DEFAULT 'pending');
        DELETE FROM quality WHERE id NOT IN (SELECT MIN(id) FROM quality GROUP BY event_id,kind,reason);
        CREATE UNIQUE INDEX IF NOT EXISTS quality_dedupe ON quality(event_id,kind,reason);''')
        columns={r[1] for r in c.execute('PRAGMA table_info(incidents)')}
        if 'assignee' not in columns: c.execute("ALTER TABLE incidents ADD COLUMN assignee TEXT NOT NULL DEFAULT ''")

def parse_dt(s):
    try:
        d=datetime.fromisoformat(str(s).replace('Z','+00:00'))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
    except Exception: return None

def fingerprint(e):
    return hashlib.sha256(json.dumps(e,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def normalized(e):
    loc=e.get('location') or {}; loc=loc if isinstance(loc,dict) else {}
    lat,lon=loc.get('latitude'),loc.get('longitude')
    lat=lat if isinstance(lat,(int,float)) and not isinstance(lat,bool) else None
    lon=lon if isinstance(lon,(int,float)) and not isinstance(lon,bool) else None
    payload=e.get('payload') or {}; payload=payload if isinstance(payload,dict) else {}
    confidence=e.get('confidence'); confidence=confidence if isinstance(confidence,(int,float)) and not isinstance(confidence,bool) else None
    def canonical_time(value):
        parsed=parse_dt(value)
        return parsed.astimezone(timezone.utc).isoformat().replace('+00:00','Z') if parsed else str(value or '')
    return {'event_id':str(e.get('event_id') or e.get('source_id') or ''), 'source_type':str(e.get('source_type') or ''), 'device_id':str(e.get('device_id') or ''), 'event_type':str(e.get('event_type') or ''), 'occurred_at':canonical_time(e.get('occurred_at')), 'received_at':canonical_time(e.get('received_at')), 'latitude':lat, 'longitude':lon, 'zone':str(loc.get('zone') or ''), 'severity':str(e.get('severity') or 'low').lower(), 'confidence':confidence, 'payload':payload, 'raw':e}

def quality_for(e, duplicate=False, conflicting_duplicate=False):
    out=[]
    def add(kind,sev,reason): out.append((kind,sev,reason))
    required=['source_type','device_id','event_type','occurred_at','received_at']
    missing=[k for k in required if not e.get(k)]
    if not (e.get('event_id') or e.get('source_id')): missing.insert(0,'event_id/source_id')
    if missing: add('incomplete','high','Missing mandatory fields: '+', '.join(missing))
    for key in ('event_id','source_id','source_type','device_id','event_type','occurred_at','received_at'):
        if key in e and e[key] is not None and not isinstance(e[key],str):
            add('invalid_field_type','high',f'{key} must be a string; the original value was preserved.')
    if e.get('source_type') and (not isinstance(e['source_type'],str) or e['source_type'] not in SOURCES): add('unknown_source','medium','Source type is not in the supported source list.')
    if not parse_dt(e.get('occurred_at')): add('malformed_timestamp','high','occurred_at is missing or not an ISO-8601 timestamp.')
    if not parse_dt(e.get('received_at')): add('malformed_timestamp','medium','received_at is missing or not an ISO-8601 timestamp.')
    conf=e.get('confidence')
    if conf is not None and (not isinstance(conf,(int,float)) or isinstance(conf,bool) or not math.isfinite(conf) or conf<0 or conf>1): add('invalid_confidence','high','Confidence must be a finite number from 0 to 1.')
    elif conf is not None and conf<.55: add('low_confidence','medium',f'Confidence {conf:.2f} is below 0.55.')
    severity=e.get('severity','low')
    if severity is not None and (not isinstance(severity,str) or severity.lower() not in SEVERITY): add('invalid_severity','medium','Severity is not one of critical, high, medium, low, or info; the original value was preserved.')
    if duplicate: add('duplicate','medium','Repeated source ID already exists; the canonical event was preserved and this submission was retained in the ingestion audit.')
    if conflicting_duplicate: add('conflicting_duplicate','high','This source ID already exists with different event content. Both submitted records were preserved in the ingestion audit; the original event was not overwritten.')
    o,r=parse_dt(e.get('occurred_at')),parse_dt(e.get('received_at'))
    if o and r and (r-o).total_seconds()>300: add('delayed','medium',f'Event arrived {(r-o).total_seconds()/60:.0f} minutes after occurrence.')
    if o and r and (r-o).total_seconds() < -30: add('timestamp_conflict','high','received_at is more than 30 seconds earlier than occurred_at.')
    loc=e.get('location') or {}
    if loc and not isinstance(loc,dict): add('invalid_location','high','location must be an object; the original value was preserved.')
    loc=loc if isinstance(loc,dict) else {}; lat,lon=loc.get('latitude'),loc.get('longitude')
    if not loc.get('zone') and lat is None and lon is None: add('missing_location','medium','No zone or coordinates; location-based correlation is unavailable.')
    if (lat is None) != (lon is None): add('incomplete_location','medium','Only one coordinate is present; location cannot be mapped reliably.')
    if lat is not None and (not isinstance(lat,(int,float)) or isinstance(lat,bool) or not math.isfinite(lat) or abs(lat)>90): add('invalid_location','high','Latitude is not a finite coordinate in the valid range.')
    if lon is not None and (not isinstance(lon,(int,float)) or isinstance(lon,bool) or not math.isfinite(lon) or abs(lon)>180): add('invalid_location','high','Longitude is not a finite coordinate in the valid range.')
    if 'payload' in e and not isinstance(e['payload'],dict): add('invalid_payload','medium','payload must be an object; the original value was preserved.')
    if e.get('event_type')=='device_offline' or (e.get('source_type')=='device_health' and e.get('severity') in ('high','critical')): add('device_health','high','Device health event indicates an offline or unhealthy device.')
    if SEVERITY.get(str(e.get('severity') or 'low').lower(),1)>=2:
        payload=e.get('payload') if isinstance(e.get('payload'),dict) else {}
        entity=payload.get('vehicle_id') or payload.get('plate') or payload.get('subject_id')
        if not entity and not loc.get('zone') and lat is None and lon is None: add('uncorrelatable','medium','No entity identifier or usable location; this event remains uncorroborated.')
    return out

def ingest_one(e):
    if not isinstance(e,dict): return {'accepted':False,'error':'Each event must be a JSON object.'}
    n=normalized(e)
    if not n['event_id']: n['event_id']='generated-'+fingerprint(e)[:20]
    with LOCK, connect() as c:
        existing=c.execute('SELECT 1 FROM events WHERE event_id=?',(n['event_id'],)).fetchone()
        existing_row=c.execute('SELECT raw FROM events WHERE event_id=?',(n['event_id'],)).fetchone()
        conflicting=bool(existing_row and fingerprint(json.loads(existing_row['raw']))!=fingerprint(e))
        issues=quality_for(e, bool(existing), conflicting)
        c.execute('INSERT INTO ingestion_records(event_id,submitted_at,disposition,raw,fingerprint) VALUES(?,?,?,?,?)',(n['event_id'],datetime.now(timezone.utc).isoformat(),'conflict' if conflicting else 'duplicate' if existing else 'accepted',json.dumps(e,ensure_ascii=False),fingerprint(e)))
        if existing:
            for k,s,r in issues: c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(n['event_id'],k,s,r))
            return {'accepted':False,'duplicate':True,'event_id':n['event_id'],'quality_issues':len(issues)}
        c.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(n['event_id'],n['source_type'],n['device_id'],n['event_type'],n['occurred_at'],n['received_at'],n['latitude'],n['longitude'],n['zone'],n['severity'],n['confidence'] if isinstance(n['confidence'],(int,float)) else None,json.dumps(n['payload']),json.dumps(n['raw']),fingerprint(e)))
        for k,s,r in issues: c.execute('INSERT INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(n['event_id'],k,s,r))
    return {'accepted':True,'event_id':n['event_id'],'quality_issues':len(issues)}

def ingest_many(events):
    """Batch writes in one SQLite transaction for predictable 50k laptop ingest."""
    results=[]; seen=set()
    with LOCK, connect() as c:
        existing={r[0]:fingerprint(json.loads(r[1])) for r in c.execute('SELECT event_id,raw FROM events')}
        event_rows=[]; issue_rows=[]; submission_rows=[]
        submitted_at=datetime.now(timezone.utc).isoformat()
        for e in events:
            # The browser uses this envelope only for a malformed JSONL line,
            # allowing valid neighboring lines to ingest while retaining the
            # exact original line in the audit table.
            if isinstance(e,dict) and set(e)=={'$raw_invalid_jsonl_line'}:
                raw=json.dumps(e['$raw_invalid_jsonl_line'],ensure_ascii=False)
                submission_rows.append((None,submitted_at,'invalid',raw,hashlib.sha256(raw.encode()).hexdigest()))
                results.append({'accepted':False,'error':'Malformed JSONL line retained in the ingestion audit.'}); continue
            if not isinstance(e,dict):
                raw=json.dumps(e,ensure_ascii=False)
                submission_rows.append((None,submitted_at,'invalid',raw,hashlib.sha256(raw.encode()).hexdigest()))
                results.append({'accepted':False,'error':'Each event must be a JSON object; the submitted value was retained in the ingestion audit.'}); continue
            n=normalized(e)
            if not n['event_id']: n['event_id']='generated-'+fingerprint(e)[:20]
            known=n['event_id'] in existing
            prior_fingerprint=existing.get(n['event_id'])
            if n['event_id'] in seen:
                prior_fingerprint=next((x[4] for x in submission_rows if x[0]==n['event_id'] and x[2] in ('accepted','conflict','duplicate')),prior_fingerprint)
            duplicate=known or n['event_id'] in seen
            conflicting=bool(duplicate and prior_fingerprint!=fingerprint(e))
            issues=quality_for(e,duplicate,conflicting)
            disposition='conflict' if conflicting else 'duplicate' if duplicate else 'accepted'
            submission_rows.append((n['event_id'],submitted_at,disposition,json.dumps(e,ensure_ascii=False),fingerprint(e)))
            if duplicate:
                for k,s,r in issues: issue_rows.append((n['event_id'],k,s,r))
                results.append({'accepted':False,'duplicate':True,'conflict':conflicting,'event_id':n['event_id'],'quality_issues':len(issues)}); continue
            seen.add(n['event_id']); event_rows.append((n['event_id'],n['source_type'],n['device_id'],n['event_type'],n['occurred_at'],n['received_at'],n['latitude'],n['longitude'],n['zone'],n['severity'],n['confidence'] if isinstance(n['confidence'],(int,float)) else None,json.dumps(n['payload']),json.dumps(n['raw']),fingerprint(e)))
            for k,s,r in issues: issue_rows.append((n['event_id'],k,s,r))
            results.append({'accepted':True,'event_id':n['event_id'],'quality_issues':len(issues)})
        c.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',event_rows)
        c.executemany('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',issue_rows)
        c.executemany('INSERT INTO ingestion_records(event_id,submitted_at,disposition,raw,fingerprint) VALUES(?,?,?,?,?)',submission_rows)
    return results

def record_invalid_request(raw_body, content_type, error):
    """Preserve the exact bytes of a syntactically invalid /ingest request."""
    encoded=base64.b64encode(raw_body).decode('ascii')
    raw=json.dumps({'raw_body_base64':encoded,'content_type':content_type,'parse_error':error},ensure_ascii=False)
    with LOCK, connect() as c:
        cur=c.execute('INSERT INTO ingestion_records(event_id,submitted_at,disposition,raw,fingerprint) VALUES(NULL,?,?,?,?)',
                      (datetime.now(timezone.utc).isoformat(),'invalid',raw,hashlib.sha256(raw_body).hexdigest()))
        return cur.lastrowid

def rows_events():
    with connect() as c: return [dict(r) for r in c.execute('SELECT * FROM events ORDER BY occurred_at DESC')]

def rebuild_incidents():
    """Deterministic conservative correlation: explicit vehicle/entity match plus zone and 20m/20min.
    Same event/device bursts collapse only within 90 seconds. Uncertain matches remain separate."""
    with LOCK, connect() as c:
        ev=[dict(r) for r in c.execute('SELECT * FROM events ORDER BY occurred_at,event_id')]
        # Clear and deterministically rebuild derived views; supports delayed/out-of-order arrivals.
        c.execute('DELETE FROM incident_events'); c.execute('DELETE FROM incidents')
        groups=[]; entity_groups={}; burst_groups={}; valid_group_times=[]; valid_group_indices=[]
        for e in ev:
            dt=parse_dt(e['occurred_at']); payload=json.loads(e['payload'] or '{}')
            entity=str(payload.get('vehicle_id') or payload.get('plate') or payload.get('subject_id') or '').strip().lower()
            lat,lon=e['latitude'],e['longitude']; chosen=None
            candidate_ids=[]
            if dt:
                # Bound lookups to groups whose first event is within the
                # correlation window. Both per-key group lists are append-only
                # and ordered, so bisect avoids repeatedly scanning history.
                cutoff=dt-timedelta(seconds=1200)
                pos=bisect_left(valid_group_times,cutoff)
                min_group_index=valid_group_indices[pos] if pos<len(valid_group_indices) else len(groups)
                if entity:
                    entity_index=entity_groups.get(entity,{})
                    same_sensor=(e['source_type'],e['device_id'])
                    for sensor_key,candidates in entity_index.items():
                        # The correlation rule requires a different source or
                        # device, so repeated records from this exact sensor
                        # can be skipped without scanning their full history.
                        if sensor_key==same_sensor: continue
                        candidate_ids.extend(candidates[bisect_left(candidates,min_group_index):])
                if e['device_id'] and e['event_type']:
                    candidates=burst_groups.get((e['device_id'],e['event_type']),[])
                    candidate_ids.extend(candidates[bisect_left(candidates,min_group_index):])
            # Merge the bounded candidate tails newest-first; a group can be
            # indexed by both its identity and its device burst key.
            for gi in sorted(set(candidate_ids),reverse=True):
                g=groups[gi]
                first=g[0]; fdt=parse_dt(first['occurred_at']); fp=json.loads(first['payload'] or '{}')
                ge=str(fp.get('vehicle_id') or fp.get('plate') or fp.get('subject_id') or '').strip().lower()
                if not fdt: continue
                delta=(dt-fdt).total_seconds()
                samezone=bool(e['zone'] and first['zone'] and e['zone'].lower()==first['zone'].lower())
                sameentity=bool(entity and ge and entity==ge)
                dist=None
                if lat is not None and lon is not None and first['latitude'] is not None and first['longitude'] is not None:
                    dist=((lat-first['latitude'])**2+(lon-first['longitude'])**2)**.5*111000
                sameplace=samezone or (dist is not None and dist<=500)
                # Avoid merging duplicate camera bursts; require a distinct device or source.
                if sameentity and sameplace and (e['device_id']!=first['device_id'] or e['source_type']!=first['source_type']): chosen=g; break
                # Device burst is a coherent incident for repeated alerting.
                if e['device_id']==first['device_id'] and e['event_type']==first['event_type'] and abs((dt-fdt).total_seconds())<=90: chosen=g; break
            if chosen is None:
                gi=len(groups); groups.append([e])
                if dt:
                    valid_group_times.append(dt); valid_group_indices.append(gi)
                    if entity:
                        sensor_key=(e['source_type'],e['device_id'])
                        entity_groups.setdefault(entity,{}).setdefault(sensor_key,[]).append(gi)
                    if e['device_id'] and e['event_type']: burst_groups.setdefault((e['device_id'],e['event_type']),[]).append(gi)
            else: chosen.append(e)
        # Device bursts and per-device event-time reversals are quality signals.
        by_device={}
        by_entity={}
        for e in ev:
            if e['device_id']: by_device.setdefault(e['device_id'],[]).append(e)
            payload=json.loads(e['payload'] or '{}'); entity=str(payload.get('vehicle_id') or payload.get('plate') or payload.get('subject_id') or '').strip().lower()
            if entity: by_entity.setdefault(entity,[]).append(e)
        for device,items in by_device.items():
            items.sort(key=lambda x: (parse_dt(x['received_at']) or datetime.min.replace(tzinfo=timezone.utc),x['event_id']))
            for prev,cur in zip(items,items[1:]):
                po,co,pr,cr=map(parse_dt,(prev['occurred_at'],cur['occurred_at'],prev['received_at'],cur['received_at']))
                if po and co and pr and cr and cr>=pr and co<po:
                    c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(cur['event_id'],'out_of_order','medium',f'Event time precedes the prior event from {device} despite a later received_at.'))
            by_type={}
            for e in items:
                dt=parse_dt(e['occurred_at'])
                if dt: by_type.setdefault(e['event_type'],[]).append((dt,e['event_id']))
            if len(items)>=12:
                c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(items[-1]['event_id'],'repeated_device','medium',f'{len(items)} events originated from {device}; check for a stuck sensor, replay, or a genuine hotspot.'))
            for typ,vals in by_type.items():
                vals.sort()
                start=0
                for j,(dt,eid) in enumerate(vals):
                    while start<j and (dt-vals[start][0]).total_seconds()>300: start+=1
                    if j-start+1>=10:
                        c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(eid,'event_spike','medium',f'{j-start+1} {typ} events from {device} occurred within five minutes.'))
                        break
        # Contradictory sensor classifications with shared identity or place anchor.
        semantic={'vehicle_detected':('vehicle_presence',1),'vehicle_present':('vehicle_presence',1),'vehicle_absent':('vehicle_presence',0),'vehicle_not_detected':('vehicle_presence',0),
                  'person_detected':('person_presence',1),'person_present':('person_presence',1),'person_absent':('person_presence',0),
                  'intrusion_alert':('intrusion',1),'intrusion_detected':('intrusion',1),'perimeter_clear':('intrusion',0),'no_intrusion':('intrusion',0),
                  'device_online':('device_health',1),'device_offline':('device_health',0),'access_granted':('access',1),'access_denied':('access',0)}
        anchored={}
        for e in ev:
            sig=semantic.get(e['event_type']); dt=parse_dt(e['occurred_at'])
            if not sig or not dt: continue
            payload=json.loads(e['payload'] or '{}'); entity=str(payload.get('vehicle_id') or payload.get('plate') or payload.get('subject_id') or '').strip().lower()
            if entity: anchor=('entity',entity)
            elif e['zone']: anchor=('zone',e['zone'].strip().lower())
            elif e['latitude'] is not None and e['longitude'] is not None: anchor=('grid',round(e['latitude'],3),round(e['longitude'],3))
            else: continue
            anchored.setdefault((anchor,sig[0]),[]).append((dt,sig[1],e))
        for (_,category),items in anchored.items():
            items.sort(key=lambda x:x[0]); last={}
            for dt,polarity,e in items:
                other=last.get(1-polarity)
                if other and (dt-other[0]).total_seconds()<=300:
                    reason=f'Conflicting {category} signals in the same identity/location anchor within five minutes: {other[1]["event_id"]} vs {e["event_id"]}.'
                    c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(other[1]['event_id'],'conflicting_evidence','high',reason))
                    c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(e['event_id'],'conflicting_evidence','high',reason))
                last[polarity]=(dt,e)
        # A repeated identity observed far apart in a short interval is a location conflict.
        for entity,items in by_entity.items():
            valid=[x for x in items if x['latitude'] is not None and x['longitude'] is not None and parse_dt(x['occurred_at'])]
            valid.sort(key=lambda x:parse_dt(x['occurred_at']))
            for prev,cur in zip(valid,valid[1:]):
                if abs((parse_dt(cur['occurred_at'])-parse_dt(prev['occurred_at'])).total_seconds())<=1200:
                    dist=((cur['latitude']-prev['latitude'])**2+(cur['longitude']-prev['longitude'])**2)**.5*111000
                    if dist>2000:
                        reason=f'Entity {entity} appears at locations {dist/1000:.1f} km apart within 20 minutes; identity or location may be wrong.'
                        c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(prev['event_id'],'conflicting_location','high',reason))
                        c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(cur['event_id'],'conflicting_location','high',reason))
        for g in groups:
            # Ignore routine informational records as incidents, but preserve all events.
            if max(SEVERITY.get(x['severity'],1) for x in g)<2 and len(g)==1: continue
            ids=[x['event_id'] for x in g]; iid='inc-'+hashlib.sha1('|'.join(sorted(ids)).encode()).hexdigest()[:12]
            severity=max((x['severity'] for x in g),key=lambda s:SEVERITY.get(s,1)); confs=[x['confidence'] for x in g if x['confidence'] is not None]
            confidence=round(sum(confs)/len(confs),2) if confs else .5
            categories=', '.join(sorted(set(x['event_type'].replace('_',' ') for x in g)))
            zones=', '.join(sorted(set(x['zone'] for x in g if x['zone']))) or 'location unconfirmed'
            title=(categories[:1].upper()+categories[1:] if categories else 'Security activity')+f' near {zones}'
            explanation='Grouped by '+('matching vehicle/subject identifier, compatible location, and a 20-minute window.' if len(g)>1 else 'single-event evidence; no cross-source link was asserted.')
            actions=['Verify the source evidence and confirm current conditions.','Assign an operator and record disposition.']
            times=[x['occurred_at'] for x in g if x['occurred_at']]
            saved=c.execute('SELECT status,assignee FROM incident_state WHERE incident_id=?',(iid,)).fetchone()
            status=saved['status'] if saved else 'open'; assignee=saved['assignee'] if saved else ''
            c.execute('INSERT INTO incidents(id,title,category,severity,confidence,status,explanation,actions,first_at,last_at,assignee) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(iid,title,categories,severity,confidence,status,explanation,json.dumps(actions),min(times) if times else '',max(times) if times else '',assignee))
            c.executemany('INSERT INTO incident_events VALUES(?,?)',[(iid,x) for x in ids])
        # Contradiction surfacing for same vehicle and close event window with opposite signals.
        for g in groups:
            if len(g)<2: continue
            types={x['event_type'] for x in g}
            opposites=[('vehicle_present','vehicle_absent'),('vehicle_detected','vehicle_absent'),('occupied','unoccupied'),('device_online','device_offline'),('intrusion_alert','perimeter_clear'),('intrusion_detected','no_intrusion'),('person_detected','person_absent'),('access_granted','access_denied')]
            for a,b in opposites:
                if a in types and b in types:
                    iid='inc-'+hashlib.sha1('|'.join(sorted(x['event_id'] for x in g)).encode()).hexdigest()[:12]
                    c.execute('INSERT OR IGNORE INTO quality(event_id,kind,severity,reason) VALUES(?,?,?,?)',(g[-1]['event_id'],'conflicting_evidence','high',f'Conflicting event types {a} and {b} appear in correlated evidence.'))
                    c.execute('UPDATE incidents SET confidence=?, explanation=explanation||? WHERE id=?',(.35,' Conflicting signals are present; treat the relationship as uncertain.',iid))

def event_json(row, include_raw=False):
    d=dict(row); raw=json.loads(d.get('raw') or '{}'); d['source_event_id']=raw.get('source_id') or raw.get('event_id') or d['event_id']; d['location']={'latitude':d.pop('latitude'),'longitude':d.pop('longitude'),'zone':d.pop('zone')}; d['payload']=json.loads(d['payload'] or '{}'); d.pop('raw',None); d.pop('fingerprint',None)
    if include_raw: d['original']=raw
    return d

def incident_where(filters=None):
    filters=filters or {}; clauses=[]; args=[]
    if filters.get('severity'): clauses.append('i.severity=?'); args.append(filters['severity'])
    if filters.get('status'): clauses.append('i.status=?'); args.append(filters['status'])
    event_terms=[]; event_args=[]
    if filters.get('zone'): event_terms.append('e.zone LIKE ?'); event_args.append('%'+filters['zone']+'%')
    if filters.get('source'): event_terms.append('e.source_type=?'); event_args.append(filters['source'])
    if filters.get('device'): event_terms.append('lower(e.device_id) LIKE ?'); event_args.append('%'+filters['device'].lower()+'%')
    if filters.get('since'): event_terms.append('julianday(e.occurred_at)>=julianday(?)'); event_args.append(filters['since'])
    if filters.get('until'): event_terms.append('julianday(e.occurred_at)<=julianday(?)'); event_args.append(filters['until'])
    if event_terms:
        clauses.append('EXISTS (SELECT 1 FROM incident_events ie JOIN events e ON e.event_id=ie.event_id WHERE ie.incident_id=i.id AND '+' AND '.join(event_terms)+')')
        args.extend(event_args)
    return (' WHERE '+' AND '.join(clauses) if clauses else ''),args

def format_incident_rows(rows,c,filters=None):
    filters=filters or {}; out=[]
    for r in rows:
        x=dict(r); x['actions']=json.loads(x['actions'])
        ev=[event_json(z) for z in c.execute('SELECT e.* FROM events e JOIN incident_events i ON e.event_id=i.event_id WHERE i.incident_id=? ORDER BY e.occurred_at,e.event_id',(x['id'],))]
        if filters.get('source'): ev=[e for e in ev if e['source_type']==filters['source']]
        if filters.get('device'): ev=[e for e in ev if filters['device'].lower() in e['device_id'].lower()]
        since=parse_dt(filters.get('since')) if filters.get('since') else None; until=parse_dt(filters.get('until')) if filters.get('until') else None
        if since: ev=[e for e in ev if parse_dt(e['occurred_at']) and parse_dt(e['occurred_at'])>=since]
        if until: ev=[e for e in ev if parse_dt(e['occurred_at']) and parse_dt(e['occurred_at'])<=until]
        if filters and any(filters.get(k) for k in ('source','device','since','until')) and not ev: continue
        x['events']=ev; x['event_ids']=[e['event_id'] for e in ev]; x['devices']=sorted(set(e['device_id'] for e in ev if e['device_id'])); x['locations']=sorted(set(e['location']['zone'] for e in ev if e['location']['zone']))
        entity_maps=[]
        for event in ev:
            payload=event.get('payload') or {}; payload=payload if isinstance(payload,dict) else {}; entity=payload.get('vehicle_id') or payload.get('plate') or payload.get('subject_id')
            entity_maps.append((('vehicle_id' if payload.get('vehicle_id') else 'plate' if payload.get('plate') else 'subject_id',str(entity)) if entity else None))
        common=set(entity_maps[0:1]) if entity_maps and entity_maps[0] else set()
        for identity in entity_maps[1:]: common &= {identity} if identity else set()
        if len(ev)==1: x['linkage_basis']='Single event; no cross-source correlation was asserted.'
        elif common:
            label,value=next(iter(common)); x['linkage_basis']=f'Matched explicit {label} {value} across compatible locations and a 20-minute time window.'
        elif len(set(x['devices']))==1 and len(set(e['event_type'] for e in ev))==1:
            x['linkage_basis']='Repeated same-device, same-event-type alerts within a 90-second burst window.'
        else: x['linkage_basis']='Grouped by deterministic correlation rules; inspect the event timeline and source IDs for each relationship.'
        x['uncertainties']=[]
        if len(ev)==1: x['uncertainties'].append('One source event only; independent corroboration is missing.')
        if any(e['confidence'] is None for e in ev): x['uncertainties'].append('Confidence is missing for one or more source events.')
        if any(e['confidence'] is not None and e['confidence']<.55 for e in ev): x['uncertainties'].append('One or more source events have low confidence.')
        if any(not e['location']['zone'] and e['location']['latitude'] is None for e in ev): x['uncertainties'].append('Location is missing for one or more source events.')
        quality_flags=[]
        if x['event_ids']:
            marks=','.join('?' for _ in x['event_ids']); quality_flags=[dict(f) for f in c.execute(f'SELECT DISTINCT kind,reason FROM quality WHERE event_id IN ({marks})',x['event_ids']).fetchall()]
        x['conflicts']=[f['reason'] for f in quality_flags if f['kind'] in ('conflicting_evidence','conflicting_location','conflicting_duplicate','timestamp_conflict')]
        x['missing_information']=[f['reason'] for f in quality_flags if f['kind'] in ('incomplete','malformed_timestamp','missing_location','incomplete_location','invalid_confidence','invalid_payload')]
        x['uncertainties'].extend(x['conflicts'])
        x['uncertainties'].extend(reason for reason in x['missing_information'] if reason not in x['uncertainties'])
        x['quality_issues']=quality_flags
        x['next_actions']=list(x['actions'])
        x['timeline']=ev
        x['related_events']=ev
        x['source_event_ids']=[e['source_event_id'] for e in ev]
        out.append(x)
    return out

def incident_order_sql():
    return 'CASE i.severity WHEN "critical" THEN 4 WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END DESC,i.last_at DESC,i.id'

def get_incident(iid):
    with connect() as c:
        row=c.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not row: return None
        rows=format_incident_rows([row],c)
        return rows[0] if rows else None

def get_incidents(filters=None):
    """Return all incidents for internal reports; API callers should use page_incidents."""
    where,args=incident_where(filters)
    with connect() as c:
        rows=c.execute('SELECT i.* FROM incidents i'+where+' ORDER BY '+incident_order_sql(),args).fetchall()
        return format_incident_rows(rows,c,filters)

def page_incidents(filters=None,page=1,page_size=12):
    filters=filters or {}; page=max(1,int(page)); page_size=min(100,max(1,int(page_size)))
    where,args=incident_where(filters); offset=(page-1)*page_size
    with connect() as c:
        total=c.execute('SELECT COUNT(*) FROM incidents i'+where,args).fetchone()[0]
        rows=c.execute('SELECT i.* FROM incidents i'+where+' ORDER BY '+incident_order_sql()+' LIMIT ? OFFSET ?',args+[page_size,offset]).fetchall()
        return {'incidents':format_incident_rows(rows,c,filters),'total':total,'page':page,'page_size':page_size,'pages':max(1,(total+page_size-1)//page_size)}

def briefing(since_value='',until_value=''):
    since=parse_dt(since_value) if since_value else None; until=parse_dt(until_value) if until_value else None
    event_clauses=[]; event_args=[]
    if since: event_clauses.append('julianday(occurred_at)>=julianday(?)'); event_args.append(since_value)
    if until: event_clauses.append('julianday(occurred_at)<=julianday(?)'); event_args.append(until_value)
    event_where=' WHERE '+' AND '.join(event_clauses) if event_clauses else ''
    with connect() as c:
        events=[event_json(r) for r in c.execute('SELECT * FROM events'+event_where+' ORDER BY occurred_at DESC',event_args)]
        window_incident=[]; window_args=[]
        if since: window_incident.append('julianday(i.last_at)>=julianday(?)'); window_args.append(since_value)
        if until: window_incident.append('julianday(i.first_at)<=julianday(?)'); window_args.append(until_value)
        win=' AND '+' AND '.join(window_incident) if window_incident else ''
        unresolved_where='i.status<>"closed"'+win
        high_where='i.status<>"closed" AND i.severity IN ("high","critical")'+win
        new_terms=[]; new_args=[]
        if since: new_terms.append('julianday(i.first_at)>=julianday(?)'); new_args.append(since_value)
        if until: new_terms.append('julianday(i.first_at)<=julianday(?)'); new_args.append(until_value)
        new_where=' AND '.join(new_terms) if new_terms else '1=1'
        unresolved_count=c.execute('SELECT COUNT(*) FROM incidents i WHERE '+unresolved_where,window_args).fetchone()[0]
        high_count=c.execute('SELECT COUNT(*) FROM incidents i WHERE '+high_where,window_args).fetchone()[0]
        new_count=c.execute('SELECT COUNT(*) FROM incidents i WHERE '+new_where,new_args).fetchone()[0]
        quality_count=c.execute('SELECT COUNT(*) FROM quality q JOIN events e ON e.event_id=q.event_id'+event_where,event_args).fetchone()[0]
        high_rows=c.execute('SELECT i.* FROM incidents i WHERE '+high_where+' ORDER BY '+incident_order_sql()+' LIMIT 8',window_args).fetchall()
        new_rows=c.execute('SELECT i.* FROM incidents i WHERE '+new_where+' ORDER BY i.first_at DESC LIMIT 10',new_args).fetchall()
        unresolved_rows=c.execute('SELECT i.* FROM incidents i WHERE '+unresolved_where+' ORDER BY '+incident_order_sql()+' LIMIT 15',window_args).fetchall()
        issues=[dict(r) for r in c.execute('SELECT q.kind,q.severity,q.reason,q.event_id FROM quality q JOIN events e ON e.event_id=q.event_id'+event_where+' ORDER BY CASE q.severity WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END DESC,q.id DESC LIMIT 40',event_args)]
        ref_terms=['i.status<>"closed"']; ref_args=[]
        if since: ref_terms.append('julianday(e.occurred_at)>=julianday(?)'); ref_args.append(since_value)
        if until: ref_terms.append('julianday(e.occurred_at)<=julianday(?)'); ref_args.append(until_value)
        refs=[r[0] for r in c.execute('SELECT DISTINCT e.event_id FROM incident_events ie JOIN incidents i ON i.id=ie.incident_id JOIN events e ON e.event_id=ie.event_id WHERE '+' AND '.join(ref_terms)+' ORDER BY e.event_id LIMIT 200',ref_args)]
        window_filters={'since':since_value if since else '', 'until':until_value if until else ''}
        high=format_incident_rows(high_rows,c,window_filters)
        new=format_incident_rows(new_rows,c,window_filters)
        unresolved=format_incident_rows(unresolved_rows,c,window_filters)
    dev={}; types={}; zones={}; health=[]
    for e in events:
        device=e['device_id']; dev[device]=dev.get(device,0)+1; types[e['event_type']]=types.get(e['event_type'],0)+1
        zone=e['location'].get('zone') or 'Unspecified'; zones[zone]=zones.get(zone,0)+1
        if e['event_type']=='device_offline' or e['source_type']=='device_health' and e['severity'] in ('high','critical'): health.append(e['event_id'])
    repeated=sorted([{'device_id':k,'events':v} for k,v in dev.items() if k and v>=3],key=lambda x:-x['events'])[:10]
    spikes=[x for x in issues if x['kind'] in ('event_spike','conflicting_evidence','conflicting_location')]
    top_types=sorted([{'event_type':k,'events':v} for k,v in types.items()],key=lambda x:-x['events'])[:8]
    top_zones=sorted([{'zone':k,'events':v} for k,v in zones.items()],key=lambda x:-x['events'])[:8]
    window=f' for {since_value or "all available history"} to {until_value or "now"}' if since or until else ' across all available history'
    return {'generated_at':datetime.now(timezone.utc).isoformat(),'window':{'since':since_value or None,'until':until_value or None},'summary':f'{unresolved_count} unresolved incidents ({new_count} new in window); {high_count} high or critical. {quality_count} quality findings across {len(events)} events{window}.','priority_incidents':high,'new_incidents':new,'unresolved_incidents':unresolved,'repeated_devices':repeated,'device_health_event_ids':health[:50],'activity_by_type':top_types,'activity_by_location':top_zones,'significant_findings':spikes[:20],'quality_issues':issues[:20],'recommended_actions':['Review critical and high incidents first, starting with the oldest unresolved items.','Investigate device-health alerts and repeated device activity before relying on affected detections.','Review conflicting evidence and location findings; confirm with an independent source before action.','Resolve high-severity data-quality findings and document uncertainty before enforcement or dispatch.'],'confidence':'Moderate; derived from event confidence where available. Links are deterministic; single-event alerts are not cross-source corroboration.','event_references':refs}

def update_incident(iid, payload):
    action=payload.get('action'); assignee=str(payload.get('assignee') or '').strip()[:100]
    allowed={'acknowledge','assign','close','reopen','false_positive'}
    if action not in allowed: return None,'Action must be acknowledge, assign, close, reopen, or false_positive.'
    with connect() as c:
        row=c.execute('SELECT status,assignee FROM incidents WHERE id=?',(iid,)).fetchone()
        if not row: return None,'Incident not found.'
        if action=='assign' and not assignee: return None,'Assignee is required for assignment.'
        status={'acknowledge':'acknowledged','close':'closed','reopen':'open','false_positive':'false_positive'}.get(action,row['status'])
        if action!='assign': assignee=row['assignee']
        c.execute('INSERT OR REPLACE INTO incident_state(incident_id,status,assignee,updated_at) VALUES(?,?,?,?)',(iid,status,assignee,datetime.now(timezone.utc).isoformat()))
        c.execute('UPDATE incidents SET status=?,assignee=? WHERE id=?',(status,assignee,iid))
        return {'id':iid,'status':status,'assignee':assignee},None

def _last_assistant_context():
    with connect() as c:
        row=c.execute("SELECT response FROM assistant_history WHERE role='assistant' ORDER BY id DESC LIMIT 1").fetchone()
    if not row: return {}
    try: return json.loads(row['response'])
    except Exception: return {}

def _save_assistant_turn(query, payload):
    with LOCK, connect() as c:
        c.execute('INSERT INTO assistant_history(created_at,role,query,response) VALUES(?,?,?,?)',(datetime.now(timezone.utc).isoformat(),'user',query,json.dumps({'query':query})))
        c.execute('INSERT INTO assistant_history(created_at,role,query,response) VALUES(?,?,?,?)',(datetime.now(timezone.utc).isoformat(),'assistant',query,json.dumps(payload)))
    return payload

def _incident_pack(incidents):
    ids=[i['id'] for i in incidents]
    evidence=[]
    for i in incidents: evidence.extend(i.get('event_ids') or [])
    conflicts=[]; missing=[]; facts=[]
    for i in incidents:
        facts.append(f"{i['id']}: {i['title']} ({i['severity']}, {i['status']}, evidence {', '.join(i.get('event_ids') or []) or 'none'}).")
        for note in i.get('uncertainties') or []:
            if 'conflict' in note.lower() or 'contradict' in note.lower(): conflicts.append(f"{i['id']}: {note}")
            elif 'missing' in note.lower() or 'one source' in note.lower() or 'low confidence' in note.lower(): missing.append(f"{i['id']}: {note}")
    return ids, evidence[:80], facts, conflicts, missing

def _pending_action(incident_id, action, assignee, query):
    pending_id='act-'+uuid.uuid4().hex[:12]
    with LOCK, connect() as c:
        c.execute('INSERT INTO assistant_pending(id,created_at,incident_id,action,assignee,query,status) VALUES(?,?,?,?,?,?,?)',
                  (pending_id,datetime.now(timezone.utc).isoformat(),incident_id,action,assignee or '',query,'pending'))
    return pending_id

def assistant_query(body):
    """Rule-based operator assistant. Grounded in stored incidents/events; never invents IDs."""
    query=str((body or {}).get('query') or '').strip()
    hinted=str((body or {}).get('incident_id') or '').strip()
    if not query: return {'error':'query is required'}
    text=query.lower()
    ctx=_last_assistant_context()
    if re.fullmatch(r'(yes|y|ok|okay|confirm|confirmed|proceed|do it|go ahead)', text):
        pending=None
        with connect() as c:
            row=c.execute("SELECT id FROM assistant_pending WHERE status='pending' ORDER BY created_at DESC LIMIT 1").fetchone()
            pending=row['id'] if row else ctx.get('pending_id')
        if pending: return assistant_confirm({'pending_id':pending,'confirmed':True,'query':query})
        payload={'answer':'There is no pending action to confirm. Ask to acknowledge, assign, close, or mark an incident as a false positive first.',
                 'facts':[],'inferences':[],'missing_information':['No pending operator action is waiting.'],'conflicts':[],'recommended_actions':[],
                 'incident_ids':ctx.get('incident_ids') or [],'evidence_event_ids':ctx.get('evidence_event_ids') or [],
                 'confidence':'high','requires_confirmation':False,'pending_id':None}
        return _save_assistant_turn(query, payload)
    if re.fullmatch(r'(no|cancel|never mind|stop)', text):
        with LOCK, connect() as c:
            c.execute("UPDATE assistant_pending SET status='cancelled' WHERE status='pending'")
        payload={'answer':'Pending action cancelled. No incident state was changed.',
                 'facts':['Operator declined the last proposed change.'],'inferences':[],'missing_information':[],'conflicts':[],
                 'recommended_actions':[],'incident_ids':[],'evidence_event_ids':[],'confidence':'high','requires_confirmation':False,'pending_id':None}
        return _save_assistant_turn(query, payload)

    inc_match=re.search(r'inc-[a-f0-9]{8,}', text)
    incident_id=hinted or (inc_match.group(0) if inc_match else None) or ((ctx.get('incident_ids') or [None])[0] if any(k in text for k in ('this incident','this alert','the incident','the alert','summar')) else None)
    zone=None
    zm=re.search(r'(?:near|at|in|around)\s+([a-z0-9][a-z0-9\-_/ ]{1,40})', text)
    if zm: zone=zm.group(1).strip().rstrip('?.!')
    device=None
    dm=re.search(r'device\s+([a-z0-9][a-z0-9\-_/]{1,40})', text)
    if dm: device=dm.group(1)
    severity=''
    if 'critical' in text: severity='critical'
    elif re.search(r'\bhigh\b', text): severity='high'
    wants_briefing=any(w in text for w in ('briefing','brief the','shift summary','daily summary','prepare a briefing'))
    wants_quality=any(w in text for w in ('quality','malformed','duplicate','unreliable','data issue'))
    wants_evidence=any(w in text for w in ('evidence','support this','why is this','source event'))
    wants_summary=any(w in text for w in ('summar','explain this incident','what happened'))
    action=None
    if re.search(r'\b(false positive|false-positive|not real|not an incident)\b', text): action='false_positive'
    elif re.search(r'\backnowledge|ack\b', text): action='acknowledge'
    elif re.search(r'\bassign\b', text): action='assign'
    elif re.search(r'\breopen\b', text): action='reopen'
    elif re.search(r'\bclose\b', text): action='close'
    assignee=''
    am=re.search(r'assign(?:ed)?(?: to)? ([a-z][a-z0-9 ._-]{1,40})', text)
    if am: assignee=am.group(1).strip()

    if action:
        if not incident_id:
            payload={'answer':'Name the incident ID to change, or ask me to list unresolved incidents first so I have context.',
                     'facts':[],'inferences':[],'missing_information':['Incident ID is required before a state-changing action.'],'conflicts':[],
                     'recommended_actions':['Ask: show unresolved high-severity incidents.'],'incident_ids':[],'evidence_event_ids':[],
                     'confidence':'high','requires_confirmation':False,'pending_id':None}
            return _save_assistant_turn(query, payload)
        target=get_incident(incident_id)
        if not target:
            payload={'answer':f'I cannot act on {incident_id} because that ID is not in stored incidents. No change was made.',
                     'facts':[],'inferences':[],'missing_information':[f'Incident {incident_id} was not found.'],'conflicts':[],
                     'recommended_actions':[],'incident_ids':[],'evidence_event_ids':[],'confidence':'high','requires_confirmation':False,'pending_id':None}
            return _save_assistant_turn(query, payload)
        if action=='assign' and not assignee:
            payload={'answer':f'Say who should own {incident_id}, for example: assign {incident_id} to Operator Chen.',
                     'facts':[f'{incident_id} is currently {target["status"]}.'],'inferences':[],'missing_information':['Assignee name is required.'],'conflicts':[],
                     'recommended_actions':[],'incident_ids':[incident_id],'evidence_event_ids':target.get('event_ids') or [],
                     'confidence':'high','requires_confirmation':False,'pending_id':None}
            return _save_assistant_turn(query, payload)
        pending_id=_pending_action(incident_id, action, assignee, query)
        ids,evidence,facts,conflicts,missing=_incident_pack([target])
        payload={'answer':f'Proposed action: {action.replace("_"," ")} on {incident_id}'+(f' (assignee {assignee})' if assignee else '')+'. This will change operator state. Reply yes to confirm or no to cancel.',
                 'facts':facts,'inferences':['State changes are never applied until you confirm.'],'missing_information':missing,'conflicts':conflicts,
                 'recommended_actions':[f'Confirm to {action.replace("_"," ")} {incident_id}.'],'incident_ids':ids,'evidence_event_ids':evidence,
                 'confidence':'high','requires_confirmation':True,'pending_id':pending_id,'pending_action':{'incident_id':incident_id,'action':action,'assignee':assignee}}
        return _save_assistant_turn(query, payload)

    if wants_briefing:
        brief=briefing()
        ids=[i['id'] for i in (brief.get('priority_incidents') or [])]
        evidence=brief.get('event_references') or []
        payload={'answer':brief.get('summary')+' '+brief.get('confidence',''),
                 'facts':[f"Priority: {i['id']} {i['title']} evidence {', '.join(i.get('event_ids') or [])}." for i in brief.get('priority_incidents') or []][:8],
                 'inferences':['Briefing is a deterministic roll-up of stored incidents and quality rows, not a generative model.'],
                 'missing_information':[] if evidence else ['No event references are available in the current window.'],
                 'conflicts':[f"{x['event_id']}: {x['reason']}" for x in brief.get('significant_findings') or [] if 'conflict' in x.get('kind','')],
                 'recommended_actions':brief.get('recommended_actions') or [],
                 'incident_ids':ids,'evidence_event_ids':evidence[:80],'confidence':brief.get('confidence','Moderate'),
                 'requires_confirmation':False,'pending_id':None,'briefing':{'summary':brief.get('summary'),'event_references':evidence[:40]}}
        return _save_assistant_turn(query, payload)

    if wants_quality:
        with connect() as c:
            issues=[dict(r) for r in c.execute('SELECT kind,severity,reason,event_id FROM quality ORDER BY CASE severity WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END DESC,id DESC LIMIT 12')]
        payload={'answer':f'{len(issues)} recent data-quality findings are listed. Original events were preserved; each finding includes a reason.',
                 'facts':[f"{x['event_id']}: {x['kind']} — {x['reason']}" for x in issues],
                 'inferences':['Quality flags are rule-based explanations, not proof that an incident is false.'],
                 'missing_information':[] if issues else ['No quality findings are stored yet.'],'conflicts':[x['reason'] for x in issues if 'conflict' in x['kind']],
                 'recommended_actions':['Inspect the cited source event IDs before relying on affected detections.'],
                 'incident_ids':[],'evidence_event_ids':[x['event_id'] for x in issues if x.get('event_id')],
                 'confidence':'high','requires_confirmation':False,'pending_id':None}
        return _save_assistant_turn(query, payload)

    list_filters={}
    if zone: list_filters['zone']=zone
    if device: list_filters['device']=device
    if 'critical' in text and not re.search(r'\bhigh\b', text): list_filters['severity']='critical'
    elif re.search(r'\bhigh\b', text): list_filters['severity']='high'
    incidents=page_incidents(list_filters,1,20)['incidents']
    if list_filters.get('severity')=='high':
        incidents=page_incidents({**list_filters,'severity':'critical'},1,10)['incidents']+incidents
    if any(w in text for w in ('unresolved','open','outstanding')):
        incidents=[i for i in incidents if i['status'] not in ('closed','false_positive')]
    if incident_id:
        target=get_incident(incident_id)
        if not target:
            payload={'answer':f'Incident {incident_id} is not in storage. I will not invent an incident or evidence.',
                     'facts':[],'inferences':[],'missing_information':[f'{incident_id} was not found.'],'conflicts':[],
                     'recommended_actions':[],'incident_ids':[],'evidence_event_ids':[],'confidence':'high','requires_confirmation':False,'pending_id':None}
            return _save_assistant_turn(query, payload)
        ids,evidence,facts,conflicts,missing=_incident_pack([target])
        if wants_evidence:
            answer=f"Evidence for {incident_id}: {', '.join(evidence) or 'no source event IDs on file'}."
        else:
            answer=f"{target['title']}. {target.get('linkage_basis') or target.get('explanation')} Status {target['status']}; confidence {target['confidence']}."
        payload={'answer':answer,'facts':facts,'inferences':[target.get('linkage_basis') or target.get('explanation') or ''],
                 'missing_information':missing,'conflicts':conflicts,'recommended_actions':target.get('actions') or [],
                 'incident_ids':ids,'evidence_event_ids':evidence,'confidence':'moderate' if missing or conflicts else 'high',
                 'requires_confirmation':False,'pending_id':None}
        return _save_assistant_turn(query, payload)

    if wants_summary and incidents:
        target=incidents[0]
        ids,evidence,facts,conflicts,missing=_incident_pack([target])
        payload={'answer':f"{target['title']}. {target.get('linkage_basis') or target.get('explanation')}",
                 'facts':facts,'inferences':[target.get('linkage_basis') or ''],'missing_information':missing,'conflicts':conflicts,
                 'recommended_actions':target.get('actions') or [],'incident_ids':ids,'evidence_event_ids':evidence,
                 'confidence':'moderate' if missing or conflicts else 'high','requires_confirmation':False,'pending_id':None}
        return _save_assistant_turn(query, payload)

    shown=incidents[:8]
    ids,evidence,facts,conflicts,missing=_incident_pack(shown)
    scope='unresolved high-severity ' if any(w in text for w in ('unresolved','open','outstanding')) and severity=='high' else ''
    place=f' near {zone}' if zone else ''
    payload={'answer':(f'Found {len(incidents)} {scope}incidents{place}.' if incidents else f'No stored incidents match that request{place}.'),
             'facts':facts,'inferences':['Only explicit identity plus compatible location/time is used to group events; nearby unrelated entities stay separate.'],
             'missing_information':missing or ([] if incidents else ['No matching incidents in storage for those filters.']),
             'conflicts':conflicts,'recommended_actions':['Open an incident ID to inspect its timeline.'] if incidents else ['Broaden filters or ingest events first.'],
             'incident_ids':ids,'evidence_event_ids':evidence,'confidence':'high' if incidents else 'moderate',
             'requires_confirmation':False,'pending_id':None}
    return _save_assistant_turn(query, payload)

def assistant_confirm(body):
    pending_id=str((body or {}).get('pending_id') or '').strip()
    confirmed=bool((body or {}).get('confirmed'))
    query=str((body or {}).get('query') or 'confirm')
    if not pending_id:
        with connect() as c:
            row=c.execute("SELECT id FROM assistant_pending WHERE status='pending' ORDER BY created_at DESC LIMIT 1").fetchone()
        pending_id=row['id'] if row else ''
    if not pending_id:
        return {'error':'No pending action. Pass pending_id from /assistant/query.'}
    with LOCK, connect() as c:
        row=c.execute('SELECT * FROM assistant_pending WHERE id=?',(pending_id,)).fetchone()
        if not row: return {'error':'Pending action not found.'}
        if row['status']!='pending': return {'error':f"Pending action is already {row['status']}."}
        if not confirmed:
            c.execute("UPDATE assistant_pending SET status='cancelled' WHERE id=?",(pending_id,))
            payload={'answer':'Action cancelled. Incident state is unchanged.','facts':[],'inferences':[],'missing_information':[],'conflicts':[],
                     'recommended_actions':[],'incident_ids':[row['incident_id']] if row['incident_id'] else [],'evidence_event_ids':[],
                     'confidence':'high','requires_confirmation':False,'pending_id':pending_id}
            return _save_assistant_turn(query, payload)
        result,error=update_incident(row['incident_id'],{'action':row['action'],'assignee':row['assignee']})
        if error:
            c.execute("UPDATE assistant_pending SET status='failed' WHERE id=?",(pending_id,))
            return {'error':error}
        c.execute("UPDATE assistant_pending SET status='confirmed' WHERE id=?",(pending_id,))
    payload={'answer':f"Confirmed: {row['action'].replace('_',' ')} on {row['incident_id']}"+(f" assigned to {row['assignee']}" if row['assignee'] else '')+f". Status is now {result['status']}.",
             'facts':[f"{result['id']} status={result['status']} assignee={result['assignee'] or 'unassigned'}."],
             'inferences':[],'missing_information':[],'conflicts':[],'recommended_actions':[],
             'incident_ids':[result['id']],'evidence_event_ids':[],'confidence':'high','requires_confirmation':False,'pending_id':pending_id,'result':result}
    return _save_assistant_turn(query, payload)

def assistant_history(limit=50):
    limit=max(1,min(200,int(limit)))
    with connect() as c:
        rows=[dict(r) for r in c.execute('SELECT id,created_at,role,query,response FROM assistant_history ORDER BY id DESC LIMIT ?',(limit,))]
    out=[]
    for row in reversed(rows):
        try: payload=json.loads(row['response'])
        except Exception: payload={'raw':row['response']}
        out.append({'id':row['id'],'created_at':row['created_at'],'role':row['role'],'query':row['query'],'payload':payload})
    return {'turns':out}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def authorize(self):
        if not PUBLIC_MODE:
            return True
        supplied=self.headers.get('Authorization','')
        if EXPECTED_AUTH and hmac.compare_digest(supplied,EXPECTED_AUTH):
            return True
        self.send_response(401)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Vary','Authorization')
        self.send_header('Cache-Control','no-store')
        body=json.dumps({'error':'Sign in to access operational data.'}).encode()
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False
    def origin_is_same_site(self):
        origin=self.headers.get('Origin')
        if not origin:
            return True
        parsed=urlparse(origin)
        host=self.headers.get('Host','')
        return parsed.scheme in ('http','https') and parsed.netloc.lower()==host.lower()
    def send_json(self,status,obj):
        b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(b)))
        if PUBLIC_MODE: self.send_header('Vary','Authorization')
        self.end_headers(); self.wfile.write(b)
    def do_OPTIONS(self):
        if not self.authorize(): return
        if not self.origin_is_same_site(): return self.send_json(403,{'error':'Cross-origin requests are not allowed.'})
        self.send_response(204); self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.end_headers()
    def do_GET(self):
        p=urlparse(self.path); q=parse_qs(p.query); path=p.path
        if path not in PUBLIC_ASSETS and not self.authorize(): return
        if path=='/': return self.serve_file(ROOT/'app'/'index.html','text/html; charset=utf-8')
        if path=='/app.js': return self.serve_file(ROOT/'app'/'app.js','text/javascript; charset=utf-8')
        if path=='/style.css': return self.serve_file(ROOT/'app'/'style.css','text/css; charset=utf-8')
        if path=='/manifest.webmanifest': return self.serve_file(ROOT/'app'/'manifest.webmanifest','application/manifest+json; charset=utf-8')
        if path=='/sw.js': return self.serve_file(ROOT/'app'/'sw.js','text/javascript; charset=utf-8')
        if path=='/offline.html': return self.serve_file(ROOT/'app'/'offline.html','text/html; charset=utf-8')
        if path=='/app-icon.svg': return self.serve_file(ROOT/'app'/'app-icon.svg','image/svg+xml')
        if path=='/app-icon-192.png': return self.serve_file(ROOT/'app'/'app-icon-192.png','image/png')
        if path=='/app-icon-512.png': return self.serve_file(ROOT/'app'/'app-icon-512.png','image/png')
        if path=='/health':
            with connect() as c: total=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            return self.send_json(200,{'status':'ok','storage':'sqlite','events':total})
        if path=='/summary':
            with connect() as c:
                events=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                incidents=c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
                open_incidents=c.execute('SELECT COUNT(*) FROM incidents WHERE status<>"closed"').fetchone()[0]
                high=c.execute('SELECT COUNT(*) FROM incidents WHERE status<>"closed" AND severity IN ("high","critical")').fetchone()[0]
                quality=c.execute('SELECT COUNT(*) FROM quality').fetchone()[0]
            return self.send_json(200,{'events':events,'incidents':incidents,'open_incidents':open_incidents,'high_critical_incidents':high,'quality_findings':quality})
        if path=='/events':
            source=q.get('source',[''])[0]; zone=q.get('zone',[''])[0]; device=q.get('device',[''])[0]; sev=q.get('severity',[''])[0]
            since=q.get('since',[''])[0]; until=q.get('until',[''])[0]; page=max(1,int(q.get('page',['1'])[0])); limit=min(500,max(1,int(q.get('limit',['200'])[0])))
            clauses=[]; args=[]
            for col,value,expr in [('source_type',source,'source_type=?'),('zone',zone,'lower(zone) LIKE ?'),('device_id',device,'lower(device_id) LIKE ?'),('severity',sev,'severity=?')]:
                if value: clauses.append(expr); args.append('%'+value.lower()+'%' if col in ('zone','device_id') else value)
            if since: clauses.append('julianday(occurred_at)>=julianday(?)'); args.append(since)
            if until: clauses.append('julianday(occurred_at)<=julianday(?)'); args.append(until)
            event_ids=list(dict.fromkeys(q.get('event_id',[])))[:100]
            if event_ids:
                clauses.append('event_id IN ('+','.join('?' for _ in event_ids)+')'); args.extend(event_ids)
            where=' WHERE '+' AND '.join(clauses) if clauses else ''; offset=(page-1)*limit
            with connect() as c:
                count=c.execute('SELECT COUNT(*) FROM events'+where,args).fetchone()[0]
                rows=c.execute('SELECT * FROM events'+where+' ORDER BY occurred_at DESC,event_id LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
            include_raw=q.get('include_raw',[''])[0].lower() in ('1','true','yes')
            return self.send_json(200,{'count':count,'page':page,'limit':limit,'pages':max(1,(count+limit-1)//limit),'events':[event_json(x,include_raw) for x in rows]})
        if path=='/incidents':
            filters={k:q.get(k,[''])[0] for k in ('severity','status','zone','source','device','since','until')}
            return self.send_json(200,page_incidents(filters,q.get('page',['1'])[0],q.get('limit',['12'])[0]))
        if path.startswith('/incidents/'):
            iid=path.rsplit('/',1)[-1]
            with connect() as c:
                row=c.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
                if not row: return self.send_json(404,{'error':'Incident not found.'})
                x=format_incident_rows([row],c)[0]
            return self.send_json(200,x)
        if path=='/quality-issues':
            source=q.get('source',[''])[0]; zone=q.get('zone',[''])[0]; device=q.get('device',[''])[0]; sev=q.get('severity',[''])[0]
            since=q.get('since',[''])[0]; until=q.get('until',[''])[0]; page=max(1,int(q.get('page',['1'])[0])); limit=min(500,max(1,int(q.get('limit',['100'])[0])))
            clauses=[]; args=[]
            for value,expr,param in [(source,'e.source_type=?',source),(zone,'lower(e.zone) LIKE ?','%'+zone.lower()+'%'),(device,'lower(e.device_id) LIKE ?','%'+device.lower()+'%'),(sev,'q.severity=?',sev)]:
                if value: clauses.append(expr); args.append(param)
            if since: clauses.append('julianday(e.occurred_at)>=julianday(?)'); args.append(since)
            if until: clauses.append('julianday(e.occurred_at)<=julianday(?)'); args.append(until)
            where=' WHERE '+' AND '.join(clauses) if clauses else ''; join=' FROM quality q JOIN events e ON e.event_id=q.event_id'
            with connect() as c:
                count=c.execute('SELECT COUNT(*)'+join+where,args).fetchone()[0]
                issues=[dict(r) for r in c.execute('SELECT q.*'+join+where+' ORDER BY q.id DESC LIMIT ? OFFSET ?',args+[limit,(page-1)*limit])]
            return self.send_json(200,{'count':count,'page':page,'limit':limit,'pages':max(1,(count+limit-1)//limit),'issues':issues})
        if path=='/ingest-records':
            event_id=q.get('event_id',[''])[0]; disposition=q.get('disposition',[''])[0]; limit=min(500,max(1,int(q.get('limit',['100'])[0])))
            clauses=[]; args=[]
            if event_id: clauses.append('event_id=?'); args.append(event_id)
            if disposition: clauses.append('disposition=?'); args.append(disposition)
            where=' WHERE '+' AND '.join(clauses) if clauses else ''
            with connect() as c:
                count=c.execute('SELECT COUNT(*) FROM ingestion_records'+where,args).fetchone()[0]
                rows=c.execute('SELECT * FROM ingestion_records'+where+' ORDER BY submission_id DESC LIMIT ?',args+[limit]).fetchall()
            records=[]
            for row in rows:
                item=dict(row); item['raw']=json.loads(item['raw']); records.append(item)
            return self.send_json(200,{'count':count,'records':records})
        if path=='/briefing': return self.send_json(200,briefing(q.get('since',[''])[0],q.get('until',[''])[0]))
        if path=='/assistant/history': return self.send_json(200,assistant_history(q.get('limit',['50'])[0]))
        return self.send_json(404,{'error':'Not found'})
    def serve_file(self,p,ct):
        b=p.read_bytes(); self.send_response(200); self.send_header('Content-Type',ct); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-cache'); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        if not self.authorize(): return
        if not self.origin_is_same_site(): return self.send_json(403,{'error':'Cross-origin requests are not allowed.'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if n>50*1024*1024: return self.send_json(413,{'error':'Request exceeds 50 MiB limit.'})
            path=urlparse(self.path).path
            raw_body=self.rfile.read(n)
            try: body=json.loads(raw_body or b'{}')
            except (json.JSONDecodeError,UnicodeDecodeError) as error:
                if path=='/ingest':
                    submission_id=record_invalid_request(raw_body,self.headers.get('Content-Type',''),str(error))
                    return self.send_json(400,{'error':'Request body must be valid JSON. The exact submitted bytes were retained in the ingestion audit.','audit_recorded':True,'submission_id':submission_id})
                raise
            if path=='/ingest':
                arr=body if isinstance(body,list) else [body]
                if len(arr)>100000: return self.send_json(413,{'error':'Batch limit is 100,000 events.'})
                results=ingest_many(arr); rebuild_incidents(); return self.send_json(200,{'submitted':len(arr),'accepted':sum(x.get('accepted',False) for x in results),'rejected':sum(not x.get('accepted',False) for x in results),'conflicts':sum(x.get('conflict',False) for x in results),'duplicates':sum(x.get('duplicate',False) for x in results),'results':results[:500]})
            if path.startswith('/incidents/') and path.endswith('/actions'):
                iid=path.split('/')[-2]; result,error=update_incident(iid,body)
                if error: return self.send_json(404 if error=='Incident not found.' else 400,{'error':error})
                return self.send_json(200,result)
            if path=='/assistant/query':
                result=assistant_query(body if isinstance(body,dict) else {})
                return self.send_json(400 if result.get('error') else 200,result)
            if path=='/assistant/confirm':
                result=assistant_confirm(body if isinstance(body,dict) else {})
                return self.send_json(400 if result.get('error') else 200,result)
            return self.send_json(404,{'error':'Not found'})
        except (json.JSONDecodeError,UnicodeDecodeError): return self.send_json(400,{'error':'Request body must be valid JSON.'})
        except Exception as e: return self.send_json(400,{'error':str(e)})

if __name__=='__main__':
    if bool(AUTH_USERNAME)!=bool(AUTH_PASSWORD):
        raise SystemExit('Set both SECOPS_USERNAME and SECOPS_PASSWORD, or leave both unset.')
    if PUBLIC_MODE and not (AUTH_USERNAME and AUTH_PASSWORD):
        raise SystemExit('Public mode requires SECOPS_USERNAME and SECOPS_PASSWORD.')
    init_db()
    port=int(os.environ.get('PORT','8000'))
    host=os.environ.get('HOST','127.0.0.1')
    server=ThreadingHTTPServer((host,port),Handler)
    print(f'SecOps platform ready at http://{host}:{port}',flush=True)
    # Open the web server immediately. Rebuilding derived incident links can
    # take a while on a large local database, so do it in the background.
    def rebuild_after_startup():
        try:
            rebuild_incidents()
        except Exception as error:
            print(f'Background incident rebuild failed: {error}',flush=True)
    threading.Thread(target=rebuild_after_startup,name='incident-rebuild',daemon=True).start()
    server.serve_forever()


