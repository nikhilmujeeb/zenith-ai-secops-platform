import json,sys,urllib.request
from pathlib import Path
events=[json.loads(x) for x in Path('data/sample_events.jsonl').read_text(encoding='utf8').splitlines() if x.strip()]
req=urllib.request.Request('http://127.0.0.1:8000/ingest',data=json.dumps(events).encode(),headers={'Content-Type':'application/json'},method='POST')
with urllib.request.urlopen(req,timeout=60) as r: print(r.read().decode())

