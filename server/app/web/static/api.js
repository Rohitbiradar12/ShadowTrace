export const state = { session: null };
export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}
export async function api(path, options = {}) {
  const url = path.startsWith('/auth/') ? `/api/v1${path}` : `/api/v1/ui${path}`;
  const headers = { Accept: 'application/json', ...options.headers };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (state.session && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = state.session.csrf_token;
  let response;
  try { response = await fetch(url, { ...options, headers, credentials: 'same-origin', body: options.body === undefined ? undefined : JSON.stringify(options.body) }); }
  catch { throw new ApiError('The server is unreachable. Check the connection and try again.', 0); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map(item => item.msg).join('; ') : data.detail;
    if (response.status === 401 && state.session && path !== '/auth/login') {
      state.session = null;
      window.dispatchEvent(new Event('session-expired'));
    }
    throw new ApiError(detail || `Request failed (${response.status})`, response.status);
  }
  return data;
}
