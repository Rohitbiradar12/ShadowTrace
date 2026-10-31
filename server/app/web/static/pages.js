import { api } from './api.js';
import { h, enc, fmt, short, date, time, ago, icon, badge, operator, heading, empty, card, table, json, facts, actionButton, deviceLink, alertLink, eventSummary, select, search, pager, query } from './ui.js';

const statuses = ['new','acknowledged','investigating','resolved','false_positive'];
const severities = ['critical','high','medium','low'];
const categories = ['process','file','usb','browser','auth','network','wifi','system','agent'];
const eventKeys = ['device_id','category','action','q','start','end','offset','order'];
const alertKeys = ['status','severity','device_id','q','offset'];
const deviceOptions = async () => (await api('/devices?limit=200')).items.map(d => [d.device_id, d.hostname]);
const eventRows = (events, session, alertId = '') => events.map(e => `<tr><td class="nowrap">${h(date(e.ts))}</td><td>${badge(e.category)}<span class="secondary-text">${h(e.action.replaceAll('_',' '))}</span></td><td class="truncate" title="${h(eventSummary(e))}">${h(eventSummary(e))}<span class="secondary-text">${h(e.user || 'User not recorded')}</span></td><td><div class="inline-actions">${actionButton('event','Inspect', {id:e.event_id})}${operator(session) && e.category === 'process' && e.action === 'process_started' && e.data.exe && e.data.create_time ? actionButton('command','Kill process', {device:e.device_id,event:e.event_id,alert:alertId,kind:'kill_process'},'danger') : ''}</div></td></tr>`);
function alertTable(items) {
  return table(['Severity','Alert','Endpoint','Status','Last seen'], items.map(a => `<tr class="sev-row sev-${h(a.severity)}"><td>${badge(a.severity)}</td><td>${alertLink(a)}</td><td>${deviceLink(a.device_id)}</td><td>${badge(a.status)}</td><td class="nowrap">${ago(a.last_seen)}</td></tr>`), 'No alerts to show', 'Matching detections will appear here. Change filters to broaden your view.');
}
export function commandTable(items, session) {
  return table(['Action','Endpoint / actor','Status','Created',''], items.map(c => `<tr><td><span class="primary-text">${h(c.action.replaceAll('_',' '))}</span><span class="secondary-text mono">${h(short(c.command_id))}</span></td><td>${deviceLink(c.device_id)}<span class="secondary-text">${h(c.actor)}</span></td><td>${badge(c.status)}</td><td class="nowrap">${ago(c.created_at)}</td><td><div class="inline-actions">${actionButton('command-detail','Details',{id:c.command_id})}${operator(session) && c.status === 'pending' ? actionButton('cancel-command','Cancel',{id:c.command_id}) : ''}</div></td></tr>`), 'No response commands', 'Commands and endpoint results appear here after an operator or rule issues a response.');
}
function trendChart(trend) {
  const hour = Math.floor(Date.now()/3600000)*3600000;
  const values = Array.from({length:24}, (_,i) => {
    const stamp = new Date(hour - (23-i)*3600000).toISOString().replace('.000Z','Z');
    return { hour: stamp, count: trend.find(row => row.hour === stamp)?.count || 0 };
  });
  const total = values.reduce((sum,v) => sum + v.count, 0);
  const peak = Math.max(0,...values.map(v => v.count));
  // Smallest even (or round-ten) ceiling so the tallest bar fills most of the plot.
  const top = peak <= 2 ? Math.max(1, peak) : peak <= 10 ? peak + (peak % 2) : Math.ceil(peak/10)*10;
  const W = 640, H = 190, left = 30, right = 6, pad = 10, bottom = 26, plotH = H - pad - bottom, step = (W - left - right) / 24, barW = Math.min(16, step * .62);
  const y = v => pad + plotH - (v/top)*plotH;
  const ticks = [...new Set([0, Math.round(top/2), top])];
  const grid = ticks.map(t => `<path class="${t ? 'chart-grid' : 'chart-axis'}" d="M${left} ${y(t).toFixed(1)}H${W-right}"/><text class="y-label" x="${left-8}" y="${(y(t)+4).toFixed(1)}" text-anchor="end">${t}</text>`).join('');
  const bars = values.map((v,i) => {
    const height = v.count ? Math.max(4,(v.count/top)*plotH) : 3, x = left + i*step + (step-barW)/2;
    return `<rect class="chart-bar${v.count ? '' : ' zero'}" x="${x.toFixed(1)}" y="${(pad+plotH-height).toFixed(1)}" width="${barW.toFixed(1)}" height="${height.toFixed(1)}" rx="3"><title>${h(time(v.hour))} UTC: ${v.count} alert${v.count===1?'':'s'}</title></rect>`;
  }).join('');
  const labels = [0,6,12,18,23].map(i => `<text x="${(left + i*step + step/2).toFixed(1)}" y="${H-6}" text-anchor="middle">${h(time(values[i].hour))}</text>`).join('');
  return `<div class="chart-summary"><strong>${fmt(total)}</strong><span>new alert${total===1?'':'s'} in 24 hours</span><span class="chart-peak">Peak ${fmt(peak)} / hour</span></div><svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="New alerts in the last 24 hours: ${total} total"><defs><linearGradient id="st-chart-fill" x1="0" y1="0" x2="0" y2="1"><stop class="chart-stop-top" offset="0"/><stop class="chart-stop-bottom" offset="1"/></linearGradient></defs>${grid}${bars}${labels}</svg>`;
}
async function overview() {
  const data = await api('/overview');
  const metrics = [
    ['Endpoints online',`${fmt(data.online)} / ${fmt(data.devices)}`,'Seen within the heartbeat window','devices','tone-green'],
    ['Open alerts',fmt(data.open_alerts),'Awaiting resolution','alerts',data.open_alerts?'tone-amber':'tone-green'],
    ['Events received',fmt(data.events_24h),'In the last 24 hours','pulse','tone-blue'],
    ['Critical alerts',fmt(data.severity.critical),'Open critical detections','shield',data.severity.critical?'critical':'tone-gray'],
  ];
  const ranking = (items, type) => items.length ? `<ol class="rank-list">${items.map((r,i) => `<li><span class="rank-number">0${i+1}</span>${type==='device' ? deviceLink(r.id) : `<a href="#/alerts?q=${enc(r.id)}">${h(r.id)}</a>`}<strong>${fmt(r.count)}</strong></li>`).join('')}</ol>` : empty('No open detections','A clear queue is a good starting point.');
  const sevTotal = severities.reduce((sum,k) => sum + (data.severity[k] || 0), 0);
  let offset = 0;
  const segments = severities.filter(k => data.severity[k]).map(k => {
    const width = data.severity[k] / sevTotal * 100, rect = `<rect class="seg-${k}" x="${offset.toFixed(2)}" y="0" width="${width.toFixed(2)}" height="10"><title>${data.severity[k]} ${k}</title></rect>`;
    offset += width; return rect;
  }).join('');
  const breakdown = `<div class="sev-breakdown"><div class="sev-head"><span>Open alerts by severity</span><span>${fmt(sevTotal)} open</span></div><svg class="sev-bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="Open alerts by severity: ${severities.map(k => `${data.severity[k] || 0} ${k}`).join(', ')}">${sevTotal ? segments : '<rect class="seg-empty" width="100" height="10"/>'}</svg><ul class="sev-legend">${severities.map(k => `<li><span class="dot seg-${k}"></span>${k}<strong>${fmt(data.severity[k] || 0)}</strong></li>`).join('')}</ul></div>`;
  const feed = data.feed.length ? `<ul class="feed">${data.feed.map(e => `<li><span class="status-dot cat-${h(e.category)}"></span><div><a href="#/events?device_id=${enc(e.device_id)}">${h(e.action.replaceAll('_',' '))}</a><span class="secondary-text truncate">${h(eventSummary(e))}</span></div><time>${h(time(e.received_at))}</time></li>`).join('')}</ul>` : empty('Waiting for activity','Enroll an endpoint to start collecting events.');
  return heading('Security overview','A current view of endpoint activity and the alerts that need your attention.', '<a class="button primary" href="#/alerts">Review alerts →</a>') +
    `<div class="metric-grid">${metrics.map(([label,value,hint,mark,cls]) => `<section class="metric ${cls}"><span class="metric-icon">${icon(mark)}</span><p>${h(label)}</p><strong>${h(value)}</strong><small>${h(hint)}</small></section>`).join('')}</div>` +
    `<div class="grid-two">${card('Alert activity',trendChart(data.trend)+breakdown,'Last 24 hours · new incidents')}${card('Top detection rules',ranking(data.top_rules,'rule'),'Open alerts by rule','<a href="#/rules">View rules ↗</a>')}</div>` +
    card('Recent alerts',alertTable(data.recent_alerts),'Latest detections and triage state','<a href="#/alerts">View all alerts ↗</a>') +
    `<div class="grid-two grid-equal">${card('Activity feed',feed,'Most recently received events','<a href="#/events">Explore events ↗</a>')}${card('Endpoints to review',ranking(data.top_devices,'device'),'Most open alerts','<a href="#/devices">All endpoints ↗</a>')}</div>`;
}
async function alerts(params) {
  const [data, devices] = await Promise.all([api(`/alerts?${query(params,alertKeys)}`),deviceOptions()]);
  return heading('Alert queue','Review detections, investigate evidence, and record a decision.') +
    `<form class="filters" data-filter="alerts">${search(params,'Search title or rule')}${select('severity','Severity',severities,params.get('severity'))}${select('status','Status',statuses,params.get('status'))}${select('device_id','Endpoint',devices,params.get('device_id'))}<button class="button primary">Apply filters</button><a class="button" href="#/alerts">Reset</a></form>` +
    card('Detections',alertTable(data.items)+pager(data,'alerts',params),`${fmt(data.total)} matching alerts`);
}
async function alertDetail(id, session) {
  const {alert:a,device,events,notifications,commands} = await api(`/alerts/${enc(id)}`);
  const start = new Date(new Date(a.first_event_at).getTime()-900000).toISOString();
  const end = new Date(new Date(a.last_event_at).getTime()+900000).toISOString();
  const actions = `<a class="button" href="#/timeline?${h(new URLSearchParams({device_id:a.device_id,start,end}))}">Open timeline</a><a class="button primary" href="/reports/${enc(id)}" target="_blank" rel="noopener">Incident report ↗</a>`;
  const history = a.history.length ? `<ol class="note-list">${a.history.map(item => `<li><strong>${h(item.actor)}</strong>${item.status ? badge(item.status) : ''}<div><small>${h(date(item.at))}</small></div>${item.note ? `<p>${h(item.note)}</p>` : ''}</li>`).join('')}</ol>` : empty('No triage notes yet','Record your findings so the next investigator has context.');
  const form = operator(session) ? `<form data-form="triage" data-id="${h(id)}"><label for="triage-status">Status</label><select id="triage-status" name="status">${statuses.map(s=>`<option value="${s}" ${s===a.status?'selected':''}>${h(s.replaceAll('_',' '))}</option>`).join('')}</select><label for="triage-note">Investigation note (optional)</label><textarea id="triage-note" name="note" maxlength="2000" placeholder="What did you find? What happens next?"></textarea><button class="button primary" type="submit">Save triage</button></form>` : '<p class="section-description">Your viewer role can inspect this incident. An analyst or administrator can update triage.</p>';
  const delivery = table(['Channel','Status','Attempts',''],notifications.map(n=>`<tr><td>${h(n.channel)}</td><td>${badge(n.status)}${n.last_error?`<span class="secondary-text">${h(n.last_error)}</span>`:''}</td><td>${n.attempts}</td><td>${session.user.role==='admin'&&['failed','disabled','unconfigured'].includes(n.status)?actionButton('retry-notification','Retry',{id:n.notification_id}):''}</td></tr>`),'No delivery jobs','This rule has no configured notification channels.');
  const glow = {critical:'red',high:'orange',medium:'amber',low:'blue'}[a.severity] || 'gray';
  return heading(a.title,`${a.rule_id} · ${device.hostname} · ${fmt(a.occurrence_count)} occurrence${a.occurrence_count===1?'':'s'}`,actions,{meta:`${badge(a.severity)}${badge(a.status)}<span class="badge neutral mono">${h(a.rule_id)}</span>`,cls:`hero glow-${glow}`}) +
    `<div class="detail-grid"><div>${card('Incident details',(a.mitre.length?`<div class="rule-tags">${a.mitre.map(t=>`<span class="badge neutral">MITRE ${h(t)}</span>`).join('')}</div>`:'')+facts([['Alert ID',a.alert_id],['Endpoint',device.hostname],['First event',date(a.first_event_at)],['Last event',date(a.last_event_at)],['Suggested response',a.suggested_action?.replaceAll('_',' ')||'Manual review']]))}${card('Investigation activity',history+form)}</div><div>${card('Endpoint response',`<p class="section-description">Commands require endpoint opt-in and return their result through the heartbeat. Review the evidence before responding.</p>${operator(session)&&device.os==='windows'?actionButton('command','Lock workstation',{device:a.device_id,alert:id,kind:'lock_workstation'},'danger'):'<p class="muted">Response actions are available to operators on Windows endpoints.</p>'}`)}${card('Notification delivery',delivery)}</div></div>` +
    card('Evidence',table(['Timestamp','Activity','Context','Actions'],eventRows(events,session,id),'Evidence unavailable','The linked event may have been removed. Verify the incident report for integrity findings.'),`${events.length} linked event${events.length===1?'':'s'}`) + card('Response history',commandTable(commands,session),'Commands linked to this incident');
}
async function devices(params, session) {
  const data = await api(`/devices?${query(params,['q','offset'])}`);
  return heading('Endpoints','Monitor connectivity and find the devices that need investigation.',session.user.role==='admin'?'<a class="button primary" href="#/settings">Enroll an endpoint</a>':'')+
    `<form class="filters" data-filter="devices">${search(params,'Search hostname')}<button class="button primary">Search</button></form>`+
    card('Device inventory',table(['Endpoint','Status','Open alerts','Events','Last seen'],data.items.map(d=>`<tr><td>${deviceLink(d.device_id,d.hostname)}<span class="secondary-text">${h(d.os)} · Agent ${h(d.agent_version)}</span></td><td>${badge(d.online?'online':'offline')}</td><td>${d.open_alerts?`<a href="#/alerts?device_id=${enc(d.device_id)}">${fmt(d.open_alerts)} open</a>`:'<span class="muted">0 open</span>'}</td><td>${fmt(d.chain_length)}</td><td class="nowrap">${ago(d.last_seen)}</td></tr>`),'No enrolled endpoints','Create an enrollment token in Settings, then enroll and run an agent.')+pager(data,'devices',params),`${fmt(data.total)} enrolled endpoints`);
}
async function deviceDetail(id, session) {
  const {device:d,alerts,processes,commands} = await api(`/devices/${enc(id)}`);
  return heading(d.hostname,`${d.os_version} · Agent ${d.agent_version}`,`<a class="button" href="#/timeline?device_id=${enc(id)}">View timeline</a>${actionButton('verify','Verify event chain',{device:id})}${operator(session)&&d.os==='windows'?actionButton('command','Lock workstation',{device:id,kind:'lock_workstation'},'danger'):''}`,{meta:`${badge(d.online?'online':'offline')}<span class="badge neutral">${h(d.os)}</span>`,cls:`hero glow-${d.online?'green':'gray'}`})+
    `<div class="grid-two grid-equal">${card('Endpoint details',facts([['Device ID',d.device_id],['Last seen',date(d.last_seen)],['Enrolled',date(d.enrolled_at)],['Last IP',d.last_ip],['Stored events',fmt(d.chain_length)],['Missing sequence numbers',fmt(d.missing_events)]]))}${card('Agent health',facts([['Buffered events',d.stats.buffered_events??'Not reported'],['Dropped events',d.stats.dropped_events??'Not reported'],['Memory',d.stats.memory_mb===undefined?'Not reported':`${d.stats.memory_mb} MB`],['CPU',d.stats.cpu_percent===undefined?'Not reported':`${d.stats.cpu_percent}%`]])+`<div class="rule-tags">${Object.entries(d.stats.collectors||{}).map(([name,status])=>`<span class="badge neutral">${h(name)}: ${h(status)}</span>`).join('')}</div>`)}</div>`+
    card('Recent alerts',alertTable(alerts))+card('Recently observed processes',table(['Observed at','Process','PID',''],processes.map(e=>`<tr><td>${h(date(e.ts))}</td><td><span class="primary-text">${h(e.data.name||'Unknown process')}</span><span class="secondary-text truncate" title="${h(e.data.exe||'')}">${h(e.data.exe||'Executable not recorded')}</span></td><td>${h(e.data.pid)}</td><td><div class="inline-actions">${actionButton('event','Inspect',{id:e.event_id})}${operator(session)&&d.os==='windows'&&e.data.exe&&e.data.create_time?actionButton('command','Kill process',{device:id,event:e.event_id,kind:'kill_process'},'danger'):''}</div></td></tr>`),'No process-start events','The process monitor reports processes that start after its initial baseline.'),'Historical observations; current identity is checked before any termination.')+card('Response history',commandTable(commands,session));
}
function eventFilters(params, devices, route) {
  const dt = value => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toISOString().slice(0,16) : '';
  return `<form class="filters" data-filter="${route}">${select('device_id','Endpoint',devices,params.get('device_id'),route==='timeline'?'Choose endpoint':'All endpoints')}${select('category','Category',categories,params.get('category'))}${search(params,'Search event metadata')}<div><label for="filter-start">From (UTC)</label><input id="filter-start" name="start" type="datetime-local" value="${h(dt(params.get('start')))}"></div><div><label for="filter-end">To (UTC)</label><input id="filter-end" name="end" type="datetime-local" value="${h(dt(params.get('end')))}"></div><div><label for="filter-action">Action (exact)</label><input id="filter-action" name="action" maxlength="64" value="${h(params.get('action')||'')}" placeholder="e.g. process_started"></div><button class="button primary">Apply filters</button><a class="button" href="#/${route}">Reset</a></form>`;
}
async function events(params, session, timeline = false) {
  const route = timeline?'timeline':'events';
  const devices = await deviceOptions();
  const filters = eventFilters(params,devices,route);
  if(timeline&&!params.get('device_id')) return heading('Forensic timeline','Follow an endpoint’s activity in chronological order.')+filters+card('Choose an endpoint',empty('Start with a device','Select an endpoint and optional time window to follow the sequence of events.'));
  const p = new URLSearchParams(params);
  if(timeline)p.set('order','asc');
  const data = await api(`/events?${query(p,eventKeys)}`);
  const exportParams = query(p,eventKeys.filter(k=>!['offset','order'].includes(k)));
  let content;
  if(timeline) content = data.items.length?`<ol class="timeline">${data.items.map(e=>`<li><div class="timeline-header"><time>${h(date(e.ts))}</time>${badge(e.category)}</div><h3>${h(e.action.replaceAll('_',' '))}</h3><p>${h(eventSummary(e))}</p><p>${h(e.user||'User not recorded')} · Sequence ${e.seq} · ${h(short(e.event_id))}</p>${actionButton('event','Inspect event',{id:e.event_id})}</li>`).join('')}</ol>`:empty('No activity in this window','Try a different date range or category.');
  else content = table(['Timestamp','Activity','Context','Actions'],eventRows(data.items,session),'No matching events','Change filters or wait for an enrolled endpoint to upload activity.');
  return heading(timeline?'Forensic timeline':'Events explorer',timeline?'Activity in time order, linked to the original stored evidence.':'Search endpoint metadata and inspect the original event record.',`<a class="button" href="/api/v1/ui/events.csv?${h(exportParams)}">Export CSV ↓</a>`)+filters+card(timeline?'Activity sequence':'Event records',content+pager(data,route,p),`${fmt(data.total)} matching events · CSV exports up to 5,000 rows`);
}
async function commands(params, session) {
  const [data,devices] = await Promise.all([api(`/commands?${query(params,['device_id','offset'])}`),deviceOptions()]);
  return heading('Response history','Track operator decisions, delivery attempts, and endpoint results.')+`<form class="filters" data-filter="commands">${select('device_id','Endpoint',devices,params.get('device_id'))}<button class="button primary">Apply filter</button></form>`+card('Command ledger',commandTable(data.items,session)+pager(data,'commands',params),`${fmt(data.total)} recorded commands`);
}
async function reports(params) {
  const data = await api(`/alerts?${query(params,alertKeys)}`);
  return heading('Incident reports','Review evidence, response history, and chain verification in a printable record.')+`<div class="callout">Open a report to verify its event chain, then choose <strong>Print / Save as PDF</strong>. A JSON download includes the same evidence for archiving.</div><form class="filters" data-filter="reports">${search(params,'Search incident or rule')}${select('severity','Severity',severities,params.get('severity'))}<button class="button primary">Find reports</button></form>`+card('Available incidents',table(['Severity','Incident','Endpoint','Status','Report'],data.items.map(a=>`<tr><td>${badge(a.severity)}</td><td>${alertLink(a)}</td><td>${deviceLink(a.device_id)}</td><td>${badge(a.status)}</td><td><a class="button small" href="/reports/${enc(a.alert_id)}" target="_blank" rel="noopener">Open report ↗</a></td></tr>`),'No incident reports yet','A report becomes available when a detection creates an alert.')+pager(data,'reports',params),`${fmt(data.total)} incidents`);
}
async function rules(params) {
  const data = await api('/rules');
  const needle = (params.get('q')||'').toLowerCase();
  const items = data.items.filter(r=>(r.id+' '+r.title+' '+r.category).toLowerCase().includes(needle));
  return heading('Detection rules',`${data.active_count} active rules · Local indicators and transparent matching conditions.`)+`<div class="callout">Rules are managed in the project’s YAML files. Validate changes and restart the server to activate them.</div><form class="filters" data-filter="rules">${search(params,'Find a rule')}<button class="button primary">Search rules</button></form><div class="rule-grid">${items.map(r=>`<section class="card rule-card"><div class="card-header"><span class="mono">${h(r.id)}</span>${badge(r.enabled?r.severity:'disabled')}</div><h3>${h(r.title)}</h3><p class="section-description">${h(r.description||`Matches ${r.category||'endpoint'} activity using the conditions below.`)}</p><div class="rule-tags">${badge(r.category||'all categories')}${r.threshold?'<span class="badge neutral">Threshold</span>':'<span class="badge neutral">Single event</span>'}${r.mitre.map(t=>`<span class="badge neutral">${h(t)}</span>`).join('')}</div><details class="rule-details"><summary>View conditions and response</summary>${json({match:r.match,exclude:r.exclude,threshold:r.threshold,response:r.response})}</details></section>`).join('')||empty('No matching rules','Try a different rule title or category.')}</div>`;
}
async function settings(session) {
  if(session.user.role!=='admin') return heading('Settings','Workspace configuration')+card('Restricted',empty('Administrator access required','Your role can investigate activity; only administrators can manage accounts and enrollment.'));
  const [config,users,tokens,audit] = await Promise.all([api('/settings'),api('/users'),api('/enrollment-tokens'),api('/audit?limit=20')]);
  const stateText = yes => yes?'Enabled':'Disabled';
  const userRows = users.items.map(u=>`<tr><td><span class="primary-text">${h(u.username)}</span><span class="secondary-text">Last sign-in: ${u.last_login ? ago(u.last_login) : 'never'}</span></td><td>${badge(u.role)}</td><td>${badge(u.disabled?'disabled':'online')}</td><td>${actionButton('manage-user','Manage',{username:u.username,role:u.role,disabled:String(u.disabled)})}</td></tr>`);
  const tokenRows = tokens.items.map(t=>`<tr><td>${h(t.note||'Enrollment token')}<span class="secondary-text">${h(date(t.created_at))}</span></td><td>${t.uses} / ${t.max_uses}</td><td>${h(date(t.expires_at))}</td><td>${actionButton('revoke-token','Revoke',{id:t.id})}</td></tr>`);
  return heading('Workspace settings','Manage operator access and endpoint enrollment. Secret values stay on the server.', '<a class="button" href="#/account">My account</a>')+
    `<div class="settings-grid">${card('Delivery & response',facts([['Alert notifications',stateText(config.notifications_enabled)],['Telegram destination',config.telegram_configured?'Configured':'Not configured'],['Email destination',config.smtp_configured?'Configured':'Not configured'],['Telegram controls',stateText(config.telegram_controls_enabled)],['Telegram operators',config.telegram_operators],['Automatic responses',stateText(config.auto_response_enabled)]])+'<p class="section-description">Configure channel credentials and response policy in the server environment, then restart.</p>')}${card('Session & collection policy',facts([['Session lifetime',`${config.session_hours} hours`],['Secure session cookie',config.secure_cookies?'HTTPS only':'Local development mode'],['Heartbeat interval',`${config.heartbeat_seconds} seconds`]])+'<p class="section-description">Use HTTPS and secure cookies when deploying beyond localhost. Endpoint response actions require separate local opt-in.</p>')}
    <section class="card settings-wide"><div class="card-header"><div><h2>Operator accounts</h2><p>Role changes and disabling an account revoke existing sessions.</p></div></div>${table(['Account','Role','Status',''],userRows)}<hr class="section-rule"><h3>Create an account</h3><form class="user-form" data-form="create-user"><div><label for="new-username">Username</label><input id="new-username" name="username" required minlength="3" maxlength="64" autocomplete="off"></div><div><label for="new-password">Password (12+ characters)</label><input id="new-password" name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password"></div><div><label for="new-role">Role</label><select id="new-role" name="role"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></div><button class="button primary">Create account</button></form></section>
    <section class="card settings-wide"><div class="card-header"><div><h2>Endpoint enrollment</h2><p>Tokens expire and are shown only once when created.</p></div>${actionButton('create-token','Create token',{},'primary')}</div>${table(['Purpose','Uses','Expires',''],tokenRows,'No enrollment tokens','Create a short-lived token to enroll a new endpoint.')}</section>
    ${card('Indicators & allowlists',Object.entries(config.indicators).map(([name,list])=>`<details class="rule-details"><summary>${h(name)} · ${list.values.length} entries</summary>${json(list)}</details>`).join(''),'Managed in intel/lists.yaml; restart after changing files.')}
    ${card('Recent administrative activity',table(['When','Actor','Action','Target'],audit.items.map(a=>`<tr><td>${h(date(a.created_at))}</td><td>${h(a.actor)}</td><td>${h(a.action.replaceAll('_',' '))}</td><td class="truncate">${h(a.target)}</td></tr>`)),'Latest 20 account and configuration actions')}</div>`;
}
function account(session) {
  return heading('My account','Update your sign-in credentials.')+card('Change password',facts([['Username',session.user.username],['Role',session.user.role]])+`<form data-form="password"><label for="current-password">Current password</label><input id="current-password" name="current_password" type="password" required autocomplete="current-password" maxlength="128"><label for="account-new-password">New password (12+ characters)</label><input id="account-new-password" name="new_password" type="password" required minlength="12" maxlength="128" autocomplete="new-password"><label for="confirm-password">Confirm new password</label><input id="confirm-password" name="confirm_password" type="password" required minlength="12" maxlength="128" autocomplete="new-password"><p class="section-description">Changing your password signs you out of all sessions.</p><button class="button primary">Change password</button></form>`);
}
export async function renderPage(route, params, session) {
  const [page,id] = route.split('/');
  if(page==='overview')return overview();
  if(page==='alerts')return id?alertDetail(id,session):alerts(params);
  if(page==='devices')return id?deviceDetail(id,session):devices(params,session);
  if(page==='events'||page==='timeline')return events(params,session,page==='timeline');
  if(page==='commands')return commands(params,session);
  if(page==='reports')return reports(params);
  if(page==='rules')return rules(params);
  if(page==='settings')return settings(session);
  if(page==='account')return account(session);
  return heading('Page not found','Choose a page from the workspace navigation.')+empty('This page is unavailable','Open Overview to return to the workspace.');
}
