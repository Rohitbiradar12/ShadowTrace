// Command palette (Ctrl/⌘+K or "/"): jump to pages, run workspace commands and search alerts/endpoints.
import { api, state } from './api.js';
import { h, enc, icon, badge } from './ui.js';

const pages = [
  ['overview', 'Overview', 'Security metrics and recent activity'],
  ['alerts', 'Alerts', 'Review and triage detections'],
  ['devices', 'Devices', 'Endpoint inventory and health'],
  ['events', 'Events explorer', 'Search collected endpoint metadata'],
  ['timeline', 'Timeline', 'Follow an endpoint in time order'],
  ['commands', 'Response history', 'Commands and endpoint results'],
  ['reports', 'Reports', 'Printable incident records'],
  ['rules', 'Detection rules', 'Active detection logic'],
  ['settings', 'Settings', 'Accounts, enrollment and delivery', 'admin'],
  ['account', 'My account', 'Change your password'],
];
let dialog, input, list, actions, items = [], remote = [], active = 0, timer, ticket = 0;

const matches = (needle, ...text) => !needle || text.join(' ').toLowerCase().includes(needle);
function go(hash) {
  if (location.hash === hash) actions.refresh(); else location.hash = hash;
}
function compute() {
  const q = input.value.trim(), needle = q.toLowerCase();
  const nav = pages
    .filter(([, , , role]) => !role || state.session?.user.role === role)
    .filter(([, label, hint]) => matches(needle, label, hint))
    .map(([route, label, hint]) => ({ group: 'Go to', icon: icon(route), label, hint, run: () => go(`#/${route}`) }));
  const commands = [
    ['theme', 'Switch light / dark theme', 'Appearance', () => actions.toggleTheme()],
    ['refresh', 'Refresh this page', 'Reload the latest data', () => actions.refresh()],
    ['logout', 'Sign out', 'End this session', () => actions.logout()],
  ].filter(([, label, hint]) => matches(needle, label, hint))
    .map(([name, label, hint, run]) => ({ group: 'Commands', icon: icon(name), label, hint, run }));
  if (!q) return [...nav, ...commands];
  const searches = [
    ['alerts', 'alerts', 'Title or rule ID'],
    ['events', 'events', 'Event metadata'],
    ['devices', 'endpoints', 'Hostname'],
  ].map(([route, noun, hint]) => ({ group: 'Search', icon: icon('search'), label: `Search ${noun} for “${q}”`, hint, run: () => go(`#/${route}?q=${enc(q)}`) }));
  return [...searches, ...remote, ...nav, ...commands];
}
function render() {
  items = compute();
  active = Math.min(active, Math.max(0, items.length - 1));
  let group = '', html = '';
  items.forEach((item, i) => {
    if (item.group !== group) { group = item.group; html += `<div class="palette-group" role="presentation">${h(group)}</div>`; }
    html += `<div class="palette-item" role="option" id="palette-option-${i}" data-index="${i}" aria-selected="false">${item.icon}<span class="palette-label">${h(item.label)}${item.hint ? `<small>${h(item.hint)}</small>` : ''}</span>${item.badge || ''}<span class="palette-enter" aria-hidden="true">↵</span></div>`;
  });
  list.innerHTML = html || '<p class="palette-empty">No matching pages or commands.</p>';
  highlight();
}
function highlight() {
  list.querySelectorAll('[data-index]').forEach(el => el.setAttribute('aria-selected', String(Number(el.dataset.index) === active)));
  const current = list.querySelector(`#palette-option-${active}`);
  if (current) { input.setAttribute('aria-activedescendant', current.id); current.scrollIntoView({ block: 'nearest' }); }
  else input.removeAttribute('aria-activedescendant');
}
async function search() {
  const q = input.value.trim(), mine = ++ticket;
  if (q.length < 2) return;
  try {
    const [alerts, devices] = await Promise.all([api(`/alerts?q=${enc(q)}&limit=5`), api(`/devices?q=${enc(q)}&limit=5`)]);
    if (mine !== ticket || !dialog.open) return;
    remote = [
      ...alerts.items.map(a => ({ group: 'Alerts', icon: icon('alerts'), label: a.title, hint: a.rule_id, badge: badge(a.severity), run: () => go(`#/alerts/${enc(a.alert_id)}`) })),
      ...devices.items.map(d => ({ group: 'Endpoints', icon: icon('devices'), label: d.hostname, hint: d.os, badge: badge(d.online ? 'online' : 'offline'), run: () => go(`#/devices/${enc(d.device_id)}`) })),
    ];
    render();
  } catch { /* live results are optional; the search shortcuts above still work */ }
}
function run(index) {
  const item = items[index];
  if (!item) return;
  dialog.close();
  item.run();
}
export function openPalette() {
  if (!state.session || dialog.open) return;
  input.value = ''; remote = []; active = 0; ticket++;
  render();
  dialog.showModal();
  input.focus();
}
export function initPalette(handlers) {
  actions = handlers;
  dialog = document.querySelector('#palette');
  input = document.querySelector('#palette-input');
  list = document.querySelector('#palette-list');
  input.addEventListener('input', () => {
    remote = []; active = 0; ticket++;
    render();
    clearTimeout(timer); timer = setTimeout(search, 180);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (items.length) { active = (active + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; highlight(); }
    } else if (event.key === 'Enter') { event.preventDefault(); run(active); }
  });
  list.addEventListener('click', event => { const el = event.target.closest('[data-index]'); if (el) run(Number(el.dataset.index)); });
  list.addEventListener('mousemove', event => {
    const el = event.target.closest('[data-index]');
    if (el && Number(el.dataset.index) !== active) { active = Number(el.dataset.index); highlight(); }
  });
  dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
  document.addEventListener('keydown', event => {
    if (!state.session) return;
    const typing = event.target.closest?.('input,textarea,select,[contenteditable="true"]');
    if (event.key.toLowerCase() === 'k' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      if (dialog.open) dialog.close(); else if (!document.querySelector('dialog[open]')) openPalette();
    } else if (event.key === '/' && !typing && !document.querySelector('dialog[open]')) {
      event.preventDefault(); openPalette();
    }
  });
}
