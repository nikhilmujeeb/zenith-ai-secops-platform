const $=s=>document.querySelector(s);
let active='incidents',incidentPage=1,listPage=1,cache={};
const INCIDENT_SIZE=12,LIST_SIZE=100,EVENT_SIZE=100,esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function request(path,options={}){const headers=new Headers(options.headers||{}),auth=sessionStorage.getItem('zenith-auth');if(auth)headers.set('Authorization',auth);const r=await fetch(path,{...options,headers});if(r.status===401){sessionStorage.removeItem('zenith-auth');$('#sign-out').hidden=true;showLogin()}return r}
async function api(path){const r=await request(path);if(!r.ok)throw Error(r.status===401?'Sign in required.':'Request failed: '+r.status);return r.json()}
function showLogin(){document.body.classList.remove('auth-pending');document.body.classList.add('auth-required');const panel=$('#login-screen');if(panel.hidden){panel.innerHTML='<form id="login-form" class="login-card"><div class="eyebrow">SECURE ACCESS</div><h2>Sign in to Zenith</h2><p>Enter the app credentials set when public access was started.</p><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Sign in</button><p id="login-error" class="login-error" role="alert"></p></form>';panel.hidden=false;$('#login-form').onsubmit=async e=>{e.preventDefault();const form=new FormData(e.currentTarget),username=String(form.get('username')||''),password=String(form.get('password')||'');let candidate;try{candidate='Basic '+btoa(unescape(encodeURIComponent(username+':'+password)))}catch(_){$('#login-error').textContent='Could not encode the supplied credentials.';return}const button=e.currentTarget.querySelector('button');button.disabled=true;$('#login-error').textContent='Checking credentials…';try{const r=await fetch('/summary',{headers:{Authorization:candidate},cache:'no-store'});if(!r.ok)throw Error('Those credentials were not accepted.');sessionStorage.setItem('zenith-auth',candidate);$('#sign-out').hidden=false;panel.hidden=true;panel.innerHTML='';await load()}catch(error){$('#login-error').textContent=error.message;button.disabled=false}}}}
function sev(s){return `<span class="badge ${esc(s)}">${esc(s)}</span>`}
function queryFilters(){const q=new URLSearchParams();for(const [id,key] of [['severity','severity'],['source','source'],['zone','zone'],['device','device']]){const value=$('#'+id).value.trim();if(value)q.set(key,value)}for(const [id,key] of [['from','since'],['until','until']]){const value=$('#'+id).value;if(value){const d=new Date(value);if(!Number.isNaN(d.valueOf()))q.set(key,d.toISOString())}}return q}
async function load(){
  try{
    const summary=await api('/summary');
    document.body.classList.remove('auth-pending','auth-required');
    $('#incident-count').textContent=Number(summary.incidents??0).toLocaleString();
    $('#quality-count').textContent=Number(summary.quality_findings??0).toLocaleString();
    $('#metrics').innerHTML=`<div class="metric"><span>EVENTS INGESTED</span><strong>${Number(summary.events??0).toLocaleString()}</strong></div><div class="metric"><span>OPEN INCIDENTS</span><strong>${Number(summary.open_incidents??0).toLocaleString()}</strong></div><div class="metric"><span>HIGH / CRITICAL</span><strong style="color:var(--red)">${Number(summary.high_critical_incidents??0).toLocaleString()}</strong></div><div class="metric"><span>QUALITY FINDINGS</span><strong style="color:var(--orange)">${Number(summary.quality_findings??0).toLocaleString()}</strong></div>`;
    const q=queryFilters();
    if(active==='incidents'){
      q.set('page',incidentPage);q.set('limit',INCIDENT_SIZE);cache.incidents=await api('/incidents?'+q.toString());
    }else if(active==='quality'){
      q.set('page',listPage);q.set('limit',LIST_SIZE);cache.quality=await api('/quality-issues?'+q.toString());
      cache.invalidSubmissions=await api('/ingest-records?disposition=invalid&limit=50');
    }else if(active==='events'){
      q.set('page',listPage);q.set('limit',EVENT_SIZE);cache.events=await api('/events?'+q.toString());
    }else if(active==='briefing'){
      cache.brief=await api('/briefing?'+q.toString());
    }else if(active==='assistant'){
      cache.history=await api('/assistant/history?limit=80');
    }
    render();
  }catch(e){if($('#login-screen').hidden){document.body.classList.remove('auth-pending');$('#content').innerHTML=`<div class="empty" style="padding:22px">Could not load data. ${esc(e.message)}</div>`}}
}
function eventcard(i){return `<article class="card"><div class="card-head"><div><h3>${esc(i.title)}</h3><div class="muted">${esc(i.category)} · ${esc(i.first_at)} → ${esc(i.last_at)} · Confidence ${Math.round(i.confidence*100)}% · ${i.events.length} source event${i.events.length===1?'':'s'}</div><div class="muted">Status <span class="status-label">${esc(i.status)}</span>${i.assignee?` · Assigned to ${esc(i.assignee)}`:''}</div></div>${sev(i.severity)}</div><div class="card-body"><p><b>Linkage basis:</b> ${esc(i.linkage_basis||i.explanation)}</p><p><b>Uncertainty:</b> ${i.uncertainties?.length?i.uncertainties.map(esc).join(' · '):'No configured conflict was detected; checks are limited to the documented rules.'}</p><p><b>Conflicts:</b> ${i.conflicts?.length?i.conflicts.map(esc).join(' · '):'None flagged'}</p><p><b>Missing information:</b> ${i.missing_information?.length?i.missing_information.map(esc).join(' · '):'None flagged'}</p><div class="evidence">${i.event_ids.map(id=>`<span class="chip">${esc(id)}</span>`).join('')} ${i.devices.map(x=>`<span class="chip">DEVICE ${esc(x)}</span>`).join('')} ${i.locations.map(x=>`<span class="chip">${esc(x)}</span>`).join('')}</div><button class="expand" data-id="${esc(i.id)}">View timeline +</button><div class="timeline" id="t-${esc(i.id)}" hidden>${i.events.map(e=>`<div class="timeline-row"><span>${esc(e.occurred_at)}</span><span><b>${esc(e.event_type)}</b> · ${esc(e.source_type)} · ${esc(e.device_id)}${e.payload.plate||e.payload.vehicle_id?` · entity ${esc(e.payload.plate||e.payload.vehicle_id)}`:''}</span><span>${esc(e.event_id)}${e.source_event_id!==e.event_id?` · source ${esc(e.source_event_id)}`:''} · ${e.confidence??'n/a'}</span></div>`).join('')}<p class="muted">Next: ${(i.next_actions||i.actions).map(esc).join(' · ')}</p></div><div class="incident-actions"><button class="incident-action" data-id="${esc(i.id)}" data-action="acknowledge">Acknowledge</button>${i.status==='closed'||i.status==='false_positive'?`<button class="incident-action" data-id="${esc(i.id)}" data-action="reopen">Reopen</button>`:`<button class="incident-action" data-id="${esc(i.id)}" data-action="close">Close incident</button><button class="incident-action" data-id="${esc(i.id)}" data-action="false_positive">False positive</button>`}<input id="assignee-${esc(i.id)}" placeholder="Operator name" value="${esc(i.assignee||'')}"><button class="incident-action" data-id="${esc(i.id)}" data-action="assign">Assign</button></div></div></article>`}
function pager(data,kind){if((data?.pages||1)<=1)return '';const page=Number(data.page||1),start=(page-1)*Number(data.page_size||data.limit||1)+1,end=Math.min(page*Number(data.page_size||data.limit||1),data.total??data.count??0),total=data.total??data.count??0;return `<div class="pagination"><span>Showing ${start}–${end} of ${Number(total).toLocaleString()} ${kind}</span><div><button id="page-prev" ${page===1?'disabled':''}>Previous</button><span>Page ${page} of ${data.pages}</span><button id="page-next" ${page===data.pages?'disabled':''}>Next</button></div></div>`}
function bindPager(data,pageName){if((data?.pages||1)<=1)return;$('#page-prev').onclick=()=>{if(pageName==='incident')incidentPage--;else listPage--;load()};$('#page-next').onclick=()=>{if(pageName==='incident')incidentPage++;else listPage++;load()}}
async function updateIncident(id,action){const assignee=$(`#assignee-${id}`)?.value||'';if(action==='assign'&&!assignee.trim()){alert('Enter an operator name before assigning.');return}try{const r=await request(`/incidents/${encodeURIComponent(id)}/actions`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,assignee})});const d=await r.json();if(!r.ok)throw Error(d.error||'Could not update incident');$('#submit-status').textContent=`${id}: ${action} saved${d.assignee?' · '+d.assignee:''}.`;await load()}catch(e){$('#submit-status').textContent='Incident update failed: '+e.message}}
function render(){
  const content=$('#content');
  if(active==='incidents'){
    const d=cache.incidents||{},list=d.incidents||[];
    content.innerHTML=list.length?list.map(eventcard).join('')+pager(d,'incidents'):'<div class="empty" style="padding:22px">No incidents match these filters.</div>';
    content.querySelectorAll('.expand').forEach(b=>b.onclick=()=>{const t=$('#t-'+b.dataset.id);t.hidden=!t.hidden;b.textContent=t.hidden?'View timeline +':'Hide timeline −'});
    content.querySelectorAll('.incident-action').forEach(b=>b.onclick=()=>updateIncident(b.dataset.id,b.dataset.action));bindPager(d,'incident');
  }else if(active==='quality'){
    const d=cache.quality||{},issues=d.issues||[];
    const invalid=cache.invalidSubmissions||{count:0,records:[]};
    const invalidPanel=`<div class="intake-audit"><button class="audit" id="invalid-intake-toggle">Malformed intake submissions (${Number(invalid.count||0).toLocaleString()})</button><div class="audit-records" id="invalid-intake-records" hidden>${(invalid.records||[]).map(r=>`<p><b>Invalid request</b> · ${esc(r.submitted_at)} · submission ${r.submission_id}<pre>${esc(JSON.stringify(r.raw,null,2))}</pre></p>`).join('')||'<p>No malformed request bodies have been recorded.</p>'}</div></div>`;
    const auditIds=new Set(),cards=issues.map(x=>{const showAudit=['duplicate','conflicting_duplicate'].includes(x.kind)&&!auditIds.has(x.event_id);if(showAudit)auditIds.add(x.event_id);return `<div class="issue"><div><b>${esc(x.kind.replaceAll('_',' '))}</b><p>${esc(x.reason)}</p><span class="chip">Event ${esc(x.event_id||'unknown')}</span>${showAudit?` <button class="audit" data-event-id="${esc(x.event_id)}">Submission history</button><div class="audit-records" id="audit-${esc(x.event_id)}" hidden></div>`:''}</div>${sev(x.severity)}</div>`});
    content.innerHTML=invalidPanel+(issues.length?cards.join('')+pager(d,'findings'):'<div class="empty" style="padding:22px">No data-quality issues match these filters.</div>');
    $('#invalid-intake-toggle').onclick=()=>{$('#invalid-intake-records').hidden=!$('#invalid-intake-records').hidden};
    content.querySelectorAll('.audit').forEach(b=>b.onclick=async()=>{const target=$('#audit-'+b.dataset.eventId);if(!target.hidden){target.hidden=true;return}try{const data=await api('/ingest-records?event_id='+encodeURIComponent(b.dataset.eventId));target.innerHTML=(data.records||[]).map(r=>`<p><b>${esc(r.disposition)}</b> · ${esc(r.submitted_at)} · submission ${r.submission_id}<pre>${esc(JSON.stringify(r.raw,null,2))}</pre></p>`).join('')||'No submission history available.';target.hidden=false}catch(e){target.textContent='Could not load submission history: '+e.message}});bindPager(d,'list');
  }else if(active==='briefing'){
    const b=cache.brief||{};content.innerHTML=`<div class="brief"><div class="eyebrow">SHIFT OPERATIONS BRIEFING · ${esc(b.generated_at)}${b.window?.since?` · FROM ${esc(b.window.since)}`:''}${b.window?.until?` · TO ${esc(b.window.until)}`:''}</div><h3>${esc(b.summary)}</h3><p>Confidence: ${esc(b.confidence)}</p><h4>Priority incidents</h4><ul>${(b.priority_incidents||[]).map(i=>`<li>${sev(i.severity)} ${esc(i.title)} · evidence ${i.event_ids.map(esc).join(', ')}</li>`).join('')||'<li>No high or critical unresolved incidents.</li>'}</ul><h4>New incidents in window</h4><ul>${(b.new_incidents||[]).map(i=>`<li>${sev(i.severity)} ${esc(i.title)} · ${i.event_ids.map(esc).join(', ')}</li>`).join('')||'<li>No new incidents in the selected window.</li>'}</ul><h4>Repeated device alerts</h4><ul>${(b.repeated_devices||[]).map(x=>`<li>${esc(x.device_id)} · ${x.events} events</li>`).join('')||'<li>No repeated device activity meets the threshold.</li>'}</ul><h4>Device health</h4><p>Health event references: ${(b.device_health_event_ids||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join(' ')||'No device-health alerts in this window.'}</p><h4>Activity trends</h4><ul>${(b.activity_by_type||[]).map(x=>`<li>${esc(x.event_type.replaceAll('_',' '))}: ${x.events} events</li>`).join('')}</ul><h4>Activity by location</h4><ul>${(b.activity_by_location||[]).map(x=>`<li>${esc(x.zone)}: ${x.events} events</li>`).join('')}</ul><h4>Significant findings</h4><ul>${(b.significant_findings||[]).map(x=>`<li>${esc(x.kind.replaceAll('_',' '))} · ${esc(x.event_id)} · ${esc(x.reason)}</li>`).join('')||'<li>No spikes or conflicts found.</li>'}</ul><h4>Data-quality focus</h4><ul>${(b.quality_issues||[]).slice(0,8).map(x=>`<li>${esc(x.kind.replaceAll('_',' '))} · ${esc(x.event_id)} · ${esc(x.reason)}</li>`).join('')||'<li>No quality findings.</li>'}</ul><h4>Recommended management actions</h4><ul>${(b.recommended_actions||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul><p>Source references: ${(b.event_references||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join(' ')}</p></div>`;
  }else if(active==='assistant'){
    content.innerHTML=renderAssistant();
    bindAssistant();
  }else{
    const d=cache.events||{},events=d.events||[];content.innerHTML=events.length?events.map(e=>`<div class="event"><div><b>${esc(e.event_type)}</b><p class="muted">${esc(e.occurred_at)} · ${esc(e.source_type)} · ${esc(e.device_id)} · ${esc(e.location.zone||'location unknown')}</p><span class="chip">${esc(e.event_id)}</span>${e.source_event_id!==e.event_id?` <span class="chip">Source ID ${esc(e.source_event_id)}</span>`:''}</div>${sev(e.severity)}</div>`).join('')+pager(d,'events'):'<div class="empty" style="padding:22px">No events match these filters.</div>';bindPager(d,'list');
  }
}
function renderAssistant(){
  const turns=(cache.history?.turns||[]).filter(t=>t.role==='assistant'||t.role==='user');
  const rows=turns.map((t,turnIndex)=>{
    if(t.role==='user') return `<div class="chat-row user"><div class="chat-bubble"><b>You</b><p>${esc(t.query||t.payload?.query||'')}</p></div></div>`;
    const p=t.payload||{},cited=[...new Set(p.evidence_event_ids||[])].slice(0,80);
    return `<div class="chat-row assistant"><div class="chat-bubble"><b>Operator assistant</b><p>${esc(p.answer||'')}</p>
      ${p.facts?.length?`<p class="muted"><b>Facts</b> · ${p.facts.map(esc).join(' · ')}</p>`:''}
      ${p.inferences?.length?`<p class="muted"><b>Inferences</b> · ${p.inferences.map(esc).join(' · ')}</p>`:''}
      ${p.missing_information?.length?`<p class="muted"><b>Missing</b> · ${p.missing_information.map(esc).join(' · ')}</p>`:''}
      ${p.conflicts?.length?`<p class="muted"><b>Conflicts</b> · ${p.conflicts.map(esc).join(' · ')}</p>`:''}
      ${p.recommended_actions?.length?`<p class="muted"><b>Recommended</b> · ${p.recommended_actions.map(esc).join(' · ')}</p>`:''}
      <div class="evidence">${(p.incident_ids||[]).map(id=>`<span class="chip">${esc(id)}</span>`).join('')}${(p.evidence_event_ids||[]).map(id=>`<span class="chip">${esc(id)}</span>`).join('')}</div>
      ${cited.length?`<button class="source-toggle" data-event-ids="${esc(JSON.stringify(cited))}" data-target="assistant-source-${turnIndex}">Show source events (${cited.length})</button><div class="source-events" id="assistant-source-${turnIndex}" hidden></div>`:''}
      <p class="muted">Confidence: ${esc(p.confidence||'n/a')}${p.requires_confirmation?' · confirmation required before any state change':''}</p>
      ${p.requires_confirmation?`<div class="incident-actions"><button class="confirm-yes" data-id="${esc(p.pending_id||'')}">Confirm</button><button class="confirm-no" data-id="${esc(p.pending_id||'')}">Cancel</button></div>`:''}
    </div></div>`;
  }).join('')||'<div class="empty" style="padding:22px">Ask about incidents, evidence, quality, or a shift briefing. Voice uses the browser; text always works offline.</div>';
  return `<div class="assistant-panel">${rows}<div class="assistant-input"><textarea id="assistant-query" placeholder="Show unresolved high-severity incidents near Gate-A"></textarea><button id="assistant-send">Ask</button><button id="assistant-talk">Hold to talk</button><span id="assistant-status" class="muted"></span></div><p class="muted">Try: “Prepare a briefing for the current shift”, “What evidence supports this alert?”, then confirm before close/assign.</p></div>`;
}
async function askAssistant(text){
  const query=(text||$('#assistant-query')?.value||'').trim();
  if(!query) return;
  $('#assistant-status').textContent='Thinking…';
  try{
    const r=await request('/assistant/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query})});
    const d=await r.json();
    if(!r.ok||d.error) throw Error(d.error||'Assistant request failed');
    speakAssistant(d.answer||'');
    cache.history=await api('/assistant/history?limit=80');
    render();
  }catch(e){$('#assistant-status').textContent=e.message}
}
function speakAssistant(text){
  if(!window.speechSynthesis||!text) return;
  window.speechSynthesis.cancel();
  const u=new SpeechSynthesisUtterance(text); u.rate=1; window.speechSynthesis.speak(u);
}
function bindAssistant(){
  $('#assistant-send').onclick=()=>askAssistant();
  $('#assistant-query').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();askAssistant()}};
  document.querySelectorAll('.source-toggle').forEach(b=>b.onclick=async()=>{const target=document.getElementById(b.dataset.target);if(!target.hidden){target.hidden=true;b.textContent=`Show source events (${JSON.parse(b.dataset.eventIds).length})`;return}try{const ids=JSON.parse(b.dataset.eventIds),q=new URLSearchParams({include_raw:'1',limit:String(Math.max(1,ids.length))});ids.forEach(id=>q.append('event_id',id));const data=await api('/events?'+q.toString());target.innerHTML=(data.events||[]).map(e=>`<article class="source-event"><div><b>${esc(e.source_event_id||e.event_id)}</b> · ${esc(e.source_type)} · ${esc(e.event_type)} · ${esc(e.occurred_at)} · ${esc(e.device_id||'device unknown')}</div><p class="muted">Original submitted event</p><pre>${esc(JSON.stringify(e.original||e,null,2))}</pre></article>`).join('')||'<p class="muted">No source records were returned for these evidence IDs.</p>';target.hidden=false;b.textContent='Hide source events'}catch(e){target.innerHTML=`<p class="muted">Could not load source events: ${esc(e.message)}</p>`;target.hidden=false}});
  document.querySelectorAll('.confirm-yes').forEach(b=>b.onclick=async()=>{const r=await request('/assistant/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pending_id:b.dataset.id,confirmed:true})});const d=await r.json();if(!r.ok){$('#assistant-status').textContent=d.error||'Confirm failed';return}speakAssistant(d.answer||'Confirmed.');cache.history=await api('/assistant/history?limit=80');render()});
  document.querySelectorAll('.confirm-no').forEach(b=>b.onclick=async()=>{await request('/assistant/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pending_id:b.dataset.id,confirmed:false})});cache.history=await api('/assistant/history?limit=80');render()});
  const talk=$('#assistant-talk');
  const Rec=window.SpeechRecognition||window.webkitSpeechRecognition;
  if(!Rec){talk.disabled=true;talk.title='Voice input is not available in this browser; type instead.';$('#assistant-status').textContent='Voice input unavailable — text still works.';return}
  let rec=null;
  const start=()=>{rec=new Rec();rec.lang='en-US';rec.interimResults=true;rec.onresult=ev=>{const t=[...ev.results].map(x=>x[0].transcript).join(' ');$('#assistant-query').value=t;$('#assistant-status').textContent=ev.results[0].isFinal?'Captured.':'Listening…'};rec.onerror=()=>{$('#assistant-status').textContent='Voice capture failed; type the question instead.'};rec.start();$('#assistant-status').textContent='Listening…'};
  const stop=()=>{try{rec&&rec.stop()}catch(_){ } if($('#assistant-query').value.trim()) askAssistant($('#assistant-query').value)};
  talk.onmousedown=start;talk.onmouseup=stop;talk.ontouchstart=e=>{e.preventDefault();start()};talk.ontouchend=e=>{e.preventDefault();stop()};
}
const tabTitles={incidents:['Incident queue','Correlated alerts with source evidence attached'],quality:['Data quality findings','Preserved original events with a clear reason for each flag'],briefing:['Shift briefing','Evidence-backed operational summary for managers'],events:['Source events','Original source records, normalized for review'],assistant:['Operations assistant','Local text and push-to-talk; state changes need confirmation']};
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');active=b.dataset.tab;incidentPage=1;listPage=1;$('#view-title').textContent=tabTitles[active][0];$('#view-subtitle').textContent=tabTitles[active][1];load()});
$('#refresh').onclick=load;$('#apply').onclick=()=>{incidentPage=1;listPage=1;load()};$('#severity').onchange=$('#source').onchange=()=>{incidentPage=1;listPage=1;load()};['zone','device','from','until'].forEach(id=>$('#'+id).onkeydown=e=>{if(e.key==='Enter'){incidentPage=1;listPage=1;load()}});
function clearIngestInputs(){$('#json-input').value='';$('#event-file').value='';$('#file-name').textContent='No file selected'}
async function sendEvents(events,label){const r=await request('/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(events)});const d=await r.json();if(!r.ok||d.error)throw Error(d.error||'Ingest failed');$('#submit-status').textContent=`${label}: accepted ${Number(d.accepted||0).toLocaleString()} / ${Number(d.submitted||0).toLocaleString()}; duplicate or invalid: ${Number(d.rejected||0).toLocaleString()}${d.conflicts?` · conflicting source IDs: ${d.conflicts}`:''}. Raw submissions are retained in the audit history.`;clearIngestInputs();await load()}
async function sendMalformedText(text,label){const r=await request('/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:text});const d=await r.json();if(!d.audit_recorded)throw Error(d.error||'Could not preserve malformed input');$('#submit-status').textContent=`${label}: invalid JSON was saved in the malformed intake audit as submission ${d.submission_id}.`;clearIngestInputs();await load()}
$('#submit').onclick=async()=>{const text=$('#json-input').value;if(!text.trim()){if($('#event-file').files[0])return await $('#file-submit').onclick();$('#submit-status').textContent='Paste JSON text here, or choose a file to upload.';return}try{const events=JSON.parse(text);await sendEvents(events,'Text submission')}catch(e){if(e instanceof SyntaxError){try{return await sendMalformedText(text,'Text submission')}catch(auditError){$('#submit-status').textContent='Invalid submission: '+auditError.message}}else $('#submit-status').textContent='Invalid submission: '+e.message}};
$('#event-file').onchange=()=>{$('#file-name').textContent=$('#event-file').files[0]?.name||'No file selected'};
$('#file-submit').onclick=async()=>{const file=$('#event-file').files[0];try{if(!file)throw Error('Choose a JSON or JSONL file first.');if(file.size>50*1024*1024)throw Error('File exceeds the 50 MiB upload limit.');const text=await file.text();let events;if(/\.(jsonl|ndjson)$/i.test(file.name)){events=text.split(/\r?\n/).filter(line=>line.trim()).map((line,i)=>{try{return JSON.parse(line)}catch(_){return {'$raw_invalid_jsonl_line':{line_number:i+1,raw_line:line,parse_error:'Invalid JSON on this line.'}}}})}else{try{events=JSON.parse(text)}catch(_){return await sendMalformedText(text,`File ${file.name}`)}}if(!Array.isArray(events))events=[events];if(!events.length)throw Error('The selected file has no events.');await sendEvents(events,`File ${file.name}`)}catch(e){$('#submit-status').textContent='File upload failed: '+e.message}};
$('#sign-out').hidden=!sessionStorage.getItem('zenith-auth');$('#sign-out').onclick=()=>{sessionStorage.removeItem('zenith-auth');$('#sign-out').hidden=true;navigator.serviceWorker?.controller?.postMessage({type:'clear-data-cache'});showLogin()};$('#now').textContent=new Date().toLocaleDateString(undefined,{month:'short',day:'2-digit',year:'numeric'});load();
let installPrompt=null;
const installButton=$('#install-app');
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();installPrompt=event;installButton.hidden=false});
window.addEventListener('appinstalled',()=>{installPrompt=null;installButton.hidden=true});
installButton.onclick=async()=>{
  if(!installPrompt){$('#submit-status').textContent='Use your browser menu and choose Install app or Add to Home Screen.';return}
  installPrompt.prompt();
  const result=await installPrompt.userChoice;
  if(result.outcome==='accepted')installButton.hidden=true;
  installPrompt=null;
};
if('serviceWorker'in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});

