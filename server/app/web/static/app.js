import { api, state } from './api.js';
import { renderPage } from './pages.js';
import { initPalette, openPalette } from './palette.js';
import { h, enc, fmt, date, icon, heading, card, empty, facts, json, badge } from './ui.js';

const main = document.querySelector('#main-content');
const dialog = document.querySelector('#action-dialog');
const dialogForm = document.querySelector('#dialog-form');
let revision = 0, modalSubmit = null, toastTimer, busy = false, refreshAfterClose = false;
const titles = { overview:'Overview',alerts:'Alerts',devices:'Devices',events:'Events explorer',timeline:'Timeline',commands:'Response history',reports:'Reports',rules:'Detection rules',settings:'Settings',account:'My account' };
for(const link of document.querySelectorAll('[data-nav]')) link.insertAdjacentHTML('afterbegin',icon(link.dataset.nav));

const lightQuery = matchMedia('(prefers-color-scheme: light)');
const currentTheme = () => document.documentElement.dataset.theme || (lightQuery.matches ? 'light' : 'dark');
function syncTheme() {
  const theme = currentTheme(), label = `Switch to ${theme === 'light' ? 'dark' : 'light'} theme`;
  document.querySelector('meta[name="theme-color"]').content = theme === 'light' ? '#f5f7fa' : '#090d13';
  document.querySelectorAll('.theme-toggle').forEach(button => { button.setAttribute('aria-label', label); button.title = label; });
}
function toggleTheme() {
  const root = document.documentElement, next = currentTheme() === 'light' ? 'dark' : 'light';
  root.classList.add('theme-switching');
  root.dataset.theme = next;
  try { localStorage.setItem('st-theme', next); } catch { /* preference simply isn't remembered */ }
  syncTheme();
  setTimeout(() => root.classList.remove('theme-switching'), 350);
}
lightQuery.addEventListener('change', syncTheme);
syncTheme();
if (/Mac|iPhone|iPad/.test(navigator.platform)) document.querySelectorAll('.kbd-mod').forEach(k => { k.textContent = '⌘'; });
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
// Count metric values up from zero when a page first renders (not on background refreshes).
function countUp() {
  if (reducedMotion.matches) return;
  main.querySelectorAll('.metric strong').forEach(node => {
    const final = node.textContent, numbers = final.match(/\d[\d,]*/g);
    if (!numbers) return;
    const targets = numbers.map(n => Number(n.replaceAll(',', ''))), start = performance.now();
    const step = now => {
      const t = Math.min(1, (now - start) / 750), eased = 1 - (1 - t) ** 3;
      let i = 0;
      node.textContent = t < 1 ? final.replace(/\d[\d,]*/g, () => fmt(Math.round(targets[i++] * eased))) : final;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}
async function updateCounts() {
  try {
    const { total } = await api('/alerts?status=new&limit=1');
    const node = document.querySelector('#nav-alert-count');
    node.textContent = total > 99 ? '99+' : String(total);
    node.title = `${total} new alert${total === 1 ? '' : 's'} awaiting triage`;
    node.hidden = !total;
  } catch { /* the badge is informational; page rendering reports real errors */ }
}
function closeNav() {
  document.body.classList.remove('nav-open');
  document.querySelector('#menu-toggle').setAttribute('aria-expanded', 'false');
}

function toast(message, error = false) {
  const node = document.querySelector('#toast');
  node.textContent = message; node.classList.toggle('error',error); node.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(()=>node.hidden=true,6500);
}
function routeInfo() {
  const [path, qs=''] = location.hash.replace(/^#\/?/,'').split('?');
  return { route: path||'overview', params:new URLSearchParams(qs) };
}
function signInView(message = '') {
  revision++;
  document.querySelector('#boot-status').hidden = true;
  document.querySelector('#workspace').hidden = true;
  document.querySelector('#login-view').hidden = false;
  document.querySelector('#login-error').textContent = message;
  document.body.classList.remove('nav-open');
  if(dialog.open)dialog.close();
  document.title = 'Sign in · ShadowTrace';
  document.querySelector('#login-username').focus();
}
function workspaceView() {
  document.querySelector('#boot-status').hidden = true;
  document.querySelector('#login-view').hidden = true;
  document.querySelector('#workspace').hidden = false;
  const {user} = state.session;
  const name = document.querySelector('#current-user');
  name.innerHTML = `<a href="#/account">${h(user.username)}</a>`;
  document.querySelector('#current-role').textContent = user.role;
  document.querySelector('#user-avatar').textContent = user.username.slice(0,2).toUpperCase();
  document.querySelectorAll('[data-admin]').forEach(el=>el.hidden=user.role!=='admin');
}
async function render(background = false) {
  if(!state.session)return;
  const ticket = ++revision, {route,params} = routeInfo(), page = route.split('/')[0];
  const focus = document.activeElement;
  if(!background) {
    main.innerHTML = '<div class="loading" role="status" aria-label="Loading page"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>';
    main.setAttribute('aria-busy','true');
  }
  document.querySelector('#topbar-title').textContent = titles[page]||'Workspace';
  document.title = `${titles[page]||'Workspace'} · ShadowTrace`;
  document.querySelectorAll('[data-nav]').forEach(a=>{
    const active = a.dataset.nav===page;
    a.classList.toggle('active',active);
    if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');
  });
  try {
    const html = await renderPage(route,params,state.session);
    if(ticket!==revision||!state.session)return;
    // Do not replace a form or steal focus if the user began interacting during a refresh.
    if(background&&(document.activeElement!==focus||dialog.open||busy))return;
    main.innerHTML = html;
    if(!background){main.classList.remove('enter');void main.offsetWidth;main.classList.add('enter');countUp();}
    updateCounts();
    document.querySelector('#refresh-status').textContent = `Updated ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`;
  } catch(error) {
    if(ticket!==revision||!state.session)return;
    if(background){document.querySelector('#refresh-status').textContent='Refresh unavailable';return;}
    main.innerHTML = heading('Unable to load this page','Your saved data has not changed.')+card('Request failed',empty(error.message,'Use Refresh to try again.'));
  } finally { if(ticket===revision)main.setAttribute('aria-busy','false'); }
}
function openDialog(title, body, submit = null, label = 'Confirm', danger = false) {
  refreshAfterClose = false;
  modalSubmit = submit;
  document.querySelector('#dialog-title').textContent = title;
  document.querySelector('#dialog-body').innerHTML = body;
  document.querySelector('#dialog-error').textContent = '';
  const button = document.querySelector('#dialog-submit');
  button.textContent = label; button.hidden = !submit; button.disabled=false;
  button.className = `button ${danger?'danger':'primary'}`;
  dialog.showModal();
  const first = dialog.querySelector('input,textarea,select');
  if(first)first.focus();
}
async function logout() {
  await api('/auth/logout',{method:'POST'});
  state.session=null; signInView();
}
document.querySelector('#login-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const form=event.currentTarget, button=form.querySelector('button');
  button.disabled=true; document.querySelector('#login-error').textContent='';
  try {
    state.session=await api('/auth/login',{method:'POST',body:Object.fromEntries(new FormData(form))});
    form.reset();workspaceView();await render();
  } catch(error){document.querySelector('#login-error').textContent=error.message;}
  finally{button.disabled=false;}
});
dialogForm.addEventListener('submit',async event=>{
  event.preventDefault();
  if(!modalSubmit)return;
  const button=document.querySelector('#dialog-submit');
  button.disabled=true;busy=true;document.querySelector('#dialog-error').textContent='';
  try {
    const keep=await modalSubmit(Object.fromEntries(new FormData(dialogForm)));
    if(keep!==false){dialog.close();await render();}
  } catch(error){document.querySelector('#dialog-error').textContent=error.message;}
  finally{button.disabled=false;busy=false;}
});

async function commandDialog(button) {
  const {device:id,event:eventId,kind,alert:alertId}=button.dataset;
  const [{device},event]=await Promise.all([api(`/devices/${enc(id)}`),eventId?api(`/events/${enc(eventId)}`):null]);
  const kill=kind==='kill_process';
  const requestId=crypto.randomUUID();
  const entries=[['Endpoint',device.hostname],['Action',kill?'Terminate the verified process':'Lock the interactive workstation']];
  if(kill)entries.push(['PID',event.data.pid],['Executable',event.data.exe],['Process started',date(event.data.create_time)]);
  const body=facts(entries)+`<div class="callout warning">${kill?'Termination can interrupt unsaved work. The agent will reject the command if the process identity changed.':'The signed-in endpoint user will need to unlock their workstation.'} Responses must be enabled on the endpoint.</div><label for="command-reason">Reason for this action</label><textarea id="command-reason" name="reason" required maxlength="500" placeholder="Record why this response is needed"></textarea><label for="command-ttl">Expires after (seconds)</label><input id="command-ttl" name="ttl" type="number" value="120" min="10" max="900" required>`;
  openDialog(kill?'Confirm process termination':'Confirm workstation lock',body,async data=>{
    const command=await api('/commands',{method:'POST',body:{device_id:id,action:kind,event_id:eventId||null,alert_id:alertId||null,reason:data.reason,ttl_seconds:Number(data.ttl),request_id:requestId}});
    toast(`Command ${command.status}. Track its result in Response history.`);
  },kill?'Queue termination':'Queue workstation lock',true);
}
async function handleAction(button) {
  const action=button.dataset.action,id=button.dataset.id;
  if(action==='toggle-theme'){toggleTheme();return;}
  if(action==='palette'){openPalette();return;}
  if(action==='close-dialog'){dialog.close();return;}
  if(action==='logout'){await logout();return;}
  if(action==='refresh'){await render();return;}
  if(action==='command'){await commandDialog(button);return;}
  if(action==='event'){
    const event=await api(`/events/${enc(id)}`);
    openDialog('Event evidence',facts([['Event ID',event.event_id],['Timestamp',date(event.ts)],['Category / action',`${event.category} / ${event.action}`],['User',event.user],['Sequence',event.seq],['Chain index',event.chain_index],['Hash',event.hash]])+`<h3>Collected metadata</h3>${json(event.data)}`);return;
  }
  if(action==='command-detail'){
    const command=await api(`/commands/${enc(id)}`);
    openDialog('Response command',`<div class="rule-tags">${badge(command.status)}</div>`+facts([['Command ID',command.command_id],['Actor',command.actor],['Reason',command.reason],['Expires',date(command.expires_at)],['Delivery attempts',command.deliveries]])+`<h3>Endpoint result</h3>${command.result?json(command.result):'<p>No endpoint result received yet.</p>'}<h3>Audit history</h3>${json(command.history)}`);return;
  }
  if(action==='cancel-command'){
    openDialog('Cancel pending command',`<p>Cancel ${h(id)} before it is delivered to the endpoint?</p>`,async()=>{await api(`/commands/${enc(id)}/cancel`,{method:'POST'});toast('Pending command cancelled.');},'Cancel command');return;
  }
  if(action==='verify'){
    const result=await api(`/devices/${enc(button.dataset.device)}/verify`,{method:'POST'});
    openDialog('Event-chain verification',`<div class="callout ${result.ok?'':'warning'}"><strong>${result.ok?'Verification passed':'Integrity failure detected'}</strong><p>${result.checked} events checked against the saved device anchor.</p>${result.reason?`<p>${h(result.reason)} · index ${h(result.broken_at_index??'unknown')}</p>`:''}</div><p>The saved anchor is held on this server. Verification does not establish independent proof of complete endpoint collection.</p>`);return;
  }
  if(action==='retry-notification'){
    openDialog('Retry notification',`<p>Queue this delivery for another attempt to its configured destination?</p>`,async()=>{await api(`/notifications/${enc(id)}/retry`,{method:'POST'});toast('Notification queued for retry.');},'Queue retry');return;
  }
  if(action==='create-token'){
    openDialog('Create enrollment token','<label for="token-note">Purpose</label><input id="token-note" name="note" maxlength="200" placeholder="e.g. College lab, room 2"><label for="token-hours">Expires in (hours)</label><input id="token-hours" name="hours" type="number" value="1" min="1" max="168" required><label for="token-uses">Maximum enrollments</label><input id="token-uses" name="max_uses" type="number" value="1" min="1" max="100" required>',async values=>{
      const token=await api('/enrollment-tokens',{method:'POST',body:{note:values.note,hours:Number(values.hours),max_uses:Number(values.max_uses)}});
      document.querySelector('#dialog-body').innerHTML=`<div class="token-box"><strong>Copy this token now. It is shown only once.</strong><code>${h(token.token)}</code><p>Expires ${h(date(token.expires_at))} · ${token.max_uses} enrollment(s)</p></div>`;
      document.querySelector('#dialog-submit').hidden=true;modalSubmit=null;refreshAfterClose=true;toast('Enrollment token created.');return false;
    },'Create token');return;
  }
  if(action==='revoke-token'){
    openDialog('Revoke enrollment token','<p>Prevent further enrollments with this token? Existing enrolled devices keep their credentials.</p>',async()=>{await api(`/enrollment-tokens/${enc(id)}`,{method:'DELETE'});toast('Token revoked.');},'Revoke token',true);return;
  }
  if(action==='manage-user'){
    const {username,role,disabled}=button.dataset;
    openDialog(`Manage ${username}`,`<label for="manage-role">Role</label><select id="manage-role" name="role">${['viewer','analyst','admin'].map(r=>`<option value="${r}" ${role===r?'selected':''}>${h(r)}</option>`).join('')}</select><label for="manage-disabled">Account access</label><select id="manage-disabled" name="disabled"><option value="false" ${disabled==='false'?'selected':''}>Enabled</option><option value="true" ${disabled==='true'?'selected':''}>Disabled</option></select><p class="section-description">Saving revokes this account’s existing sessions.</p>`,async values=>{
      await api(`/users/${enc(username)}`,{method:'PATCH',body:{role:values.role,disabled:values.disabled==='true'}});
      toast('Account updated; sessions revoked.');
      if(username===state.session.user.username){state.session=null;signInView('Your role changed. Sign in again.');}
    },'Save access');return;
  }
}
document.addEventListener('click',async event=>{
  if(document.body.classList.contains('nav-open')&&!event.target.closest('.sidebar,#menu-toggle'))closeNav();
  if(event.target.closest('.skip-link')){event.preventDefault();(state.session?main:document.querySelector('#login-username')).focus();return;}
  const button=event.target.closest('[data-action]');
  if(!button)return;
  event.preventDefault();
  if(button.disabled)return;
  button.disabled=true;
  try{await handleAction(button);}catch(error){toast(error.message,true);}finally{button.disabled=false;}
});
document.addEventListener('submit',async event=>{
  const form=event.target;
  if(form.dataset.filter){
    event.preventDefault();
    const params=new URLSearchParams();
    for(const [key,value] of new FormData(form))if(value){
      params.set(key,['start','end'].includes(key)?new Date(`${value}Z`).toISOString():value);
    }
    const next=`#/${form.dataset.filter}${params.size?'?'+params:''}`;
    if(location.hash===next)await render();else location.hash=next;
    return;
  }
  if(!form.dataset.form)return;
  event.preventDefault();
  const values=Object.fromEntries(new FormData(form)),button=form.querySelector('button[type="submit"],button:not([type])');
  if(button)button.disabled=true;busy=true;
  try{
    if(form.dataset.form==='triage'){
      await api(`/alerts/${enc(form.dataset.id)}`,{method:'PATCH',body:{status:values.status,note:values.note.trim()||null}});
      toast('Triage saved.');await render();
    }else if(form.dataset.form==='create-user'){
      await api('/users',{method:'POST',body:values});form.reset();toast('Operator account created.');await render();
    }else if(form.dataset.form==='password'){
      if(values.new_password!==values.confirm_password)throw new Error('New passwords do not match.');
      await api('/auth/password',{method:'POST',body:{current_password:values.current_password,new_password:values.new_password}});
      state.session=null;form.reset();signInView('Password changed. Sign in with your new password.');
    }
  }catch(error){toast(error.message,true);}finally{if(button)button.disabled=false;busy=false;}
});
document.querySelector('#menu-toggle').addEventListener('click',()=>{
  const open=document.body.classList.toggle('nav-open');
  document.querySelector('#menu-toggle').setAttribute('aria-expanded',String(open));
});
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeNav();});
window.addEventListener('hashchange',()=>{closeNav();render();});
window.addEventListener('session-expired',()=>signInView('Your session expired or was revoked. Sign in again.'));
dialog.addEventListener('close',()=>{modalSubmit=null;document.querySelector('#dialog-body').replaceChildren();if(refreshAfterClose&&state.session){refreshAfterClose=false;render();}});
setInterval(()=>{
  const {route}=routeInfo(), active=document.activeElement;
  if(state.session&&!document.hidden&&!busy&&!document.querySelector('dialog[open]')&&!active?.matches('input,textarea,select,button,a,summary')&&['overview','alerts','devices','commands'].includes(route))render(true);
},15000);
initPalette({toggleTheme,refresh:()=>render(),logout});
try{state.session=await api('/auth/me');workspaceView();await render();}
catch(error){signInView(error.status===401?'':error.message);}
