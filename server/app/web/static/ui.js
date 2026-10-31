export const h = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
export const enc = encodeURIComponent;
export const fmt = value => new Intl.NumberFormat('en').format(value || 0);
export const short = value => String(value || '').length > 20 ? `${String(value).slice(0, 12)}…${String(value).slice(-5)}` : String(value || '—');
export const date = value => {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'medium' }).format(d);
};
export const time = value => value ? new Date(value).toLocaleTimeString('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit' }) : '—';
const paths = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  alerts: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v1"/>',
  devices: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  events: '<path d="M5 4h14v16H5zM8 8h8m-8 4h8m-8 4h5"/>',
  timeline: '<path d="M5 3v18m0-15h14M5 12h10M5 18h14"/><circle cx="5" cy="6" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="5" cy="18" r="2"/>',
  commands: '<path d="m5 5 6 7-6 7m8 0h7"/>',
  reports: '<path d="M5 3h10l4 4v14H5zM14 3v5h5M8 12h8m-8 4h8"/>',
  rules: '<path d="M3 6h18M3 12h18M3 18h18"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="9" cy="18" r="2"/>',
  // Settings gear adapted from Feather Icons (MIT).
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>',
  shield: '<path d="M12 3 4.5 6v6c0 4.4 3.2 7.6 7.5 9 4.3-1.4 7.5-4.6 7.5-9V6L12 3Z"/><path d="m9 12 2 2 4-4"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  account: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  theme: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36L21 8m0-5v5h-5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9"/>',
};
export const icon = name => `<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.events}</svg>`;
const badgeClasses = new Set(['critical','high','medium','low','new','acknowledged','investigating','resolved','false_positive','pending','delivered','succeeded','failed','rejected','unknown','expired','cancelled','online','offline','disabled','sent','unconfigured']);
export const badge = value => `<span class="badge ${badgeClasses.has(value) ? value : 'neutral'}">${h(String(value || 'unknown').replaceAll('_', ' '))}</span>`;
export const operator = session => ['admin', 'analyst'].includes(session.user.role);
export const heading = (title, subtitle, actions = '', { meta = '', cls = '' } = {}) => `<div class="page-heading ${cls}"><div>${meta ? `<div class="heading-meta">${meta}</div>` : ''}<h1>${h(title)}</h1><p>${h(subtitle)}</p></div>${actions ? `<div class="heading-actions">${actions}</div>` : ''}</div>`;
// Relative time for recent activity; the exact UTC timestamp stays available on hover.
export const ago = value => {
  if (!value) return '—';
  const d = new Date(value), seconds = (Date.now() - d.getTime()) / 1000;
  if (Number.isNaN(seconds)) return h(value);
  const rel = seconds < 0 ? null : seconds < 45 ? 'just now' : seconds < 3600 ? `${Math.max(1, Math.round(seconds / 60))} min ago`
    : seconds < 86400 ? `${Math.round(seconds / 3600)} h ago` : seconds < 604800 ? `${Math.round(seconds / 86400)} d ago` : null;
  return `<time datetime="${h(d.toISOString())}" title="${h(date(value))} UTC">${h(rel || date(value))}</time>`;
};
export const empty = (title, subtitle) => `<div class="empty"><span class="empty-icon" aria-hidden="true"><svg class="icon" viewBox="0 0 24 24">${paths.shield}</svg></span><h2>${h(title)}</h2><p>${h(subtitle)}</p></div>`;
export const card = (title, body, subtitle = '', action = '') => `<section class="card"><div class="card-header"><div><h2>${h(title)}</h2>${subtitle ? `<p>${h(subtitle)}</p>` : ''}</div>${action}</div>${body}</section>`;
export const table = (headers, rows, emptyTitle = 'Nothing to show yet', emptyHint = 'New activity will appear here.') => rows.length ? `<div class="table-wrap"><table><thead><tr>${headers.map(v => `<th scope="col">${h(v)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : empty(emptyTitle, emptyHint);
export const json = value => `<pre>${h(JSON.stringify(value, null, 2))}</pre>`;
export const facts = entries => `<dl class="facts">${entries.map(([label, value]) => `<dt>${h(label)}</dt><dd>${h(value ?? '—')}</dd>`).join('')}</dl>`;
export const actionButton = (action, label, attrs = {}, cls = '') => `<button class="button small ${cls}" type="button" data-action="${h(action)}" ${Object.entries(attrs).map(([k,v]) => `data-${k}="${h(v)}"`).join(' ')}>${h(label)}</button>`;
export const deviceLink = (id, label = short(id)) => `<a href="#/devices/${enc(id)}" title="${h(id)}">${h(label)}</a>`;
export const alertLink = alert => `<a class="primary-text" href="#/alerts/${enc(alert.alert_id)}">${h(alert.title)}</a><span class="secondary-text">${h(alert.rule_id)}</span>`;
export const eventSummary = event => String(event.data.exe || event.data.url || event.data.path || event.data.remote_ip || event.data.target_user || event.data.ssid || event.data.threat_name || event.data.name || 'Event metadata available');
export function select(name, label, options, value = '', all = 'All') {
  return `<div><label for="filter-${h(name)}">${h(label)}</label><select id="filter-${h(name)}" name="${h(name)}">${all === null ? '' : `<option value="">${h(all)}</option>`}${options.map(item => { const [v,text] = Array.isArray(item) ? item : [item, item.replaceAll('_',' ')]; return `<option value="${h(v)}" ${String(v) === String(value) ? 'selected' : ''}>${h(text)}</option>`; }).join('')}</select></div>`;
}
export const search = (params, label = 'Search') => `<div class="search-filter"><label for="filter-q">${h(label)}</label><input id="filter-q" name="q" value="${h(params.get('q') || '')}" placeholder="Search…" maxlength="100"></div>`;
export const pager = (data, route, params) => {
  const make = offset => { const copy = new URLSearchParams(params); copy.set('offset', offset); return `#/${route}?${copy}`; };
  const offset = data.offset || 0, limit = data.limit || 50;
  return `<div class="pager"><span>${data.total ? `${fmt(offset + 1)}–${fmt(Math.min(offset + limit, data.total))} of ${fmt(data.total)}` : '0 results'}</span><div>${offset ? `<a class="button small" href="${h(make(Math.max(0, offset-limit)))}">← Previous</a>` : '<button class="button small" disabled>← Previous</button>'}${offset+limit < data.total ? `<a class="button small" href="${h(make(offset+limit))}">Next →</a>` : '<button class="button small" disabled>Next →</button>'}</div></div>`;
};
export const query = (params, keys) => new URLSearchParams([...params].filter(([key,value]) => keys.includes(key) && value)).toString();
