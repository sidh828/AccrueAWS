import { useCallback, useEffect, useRef, useState } from 'react';

const API = import.meta.env.VITE_API_BASE || '';

const TOKEN_STORAGE_KEY = 'accrue_dashboard_token';

// The guard prints a URL containing #token=... Opening it once on a device
// keeps the token on that device (localStorage), so a new tab, such as the
// one a phone alert opens (alerts never carry the token), still works. It's
// read from the URL fragment, which isn't sent in page requests, then taken
// out of the address bar. A token the guard refuses is dropped (forgetToken).
function stored(read) {
  try { return read(); } catch { return null; } // storage can be blocked
}

function getDashboardToken() {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const tokenFromUrl = params.get('token');

  if (tokenFromUrl) {
    stored(() => localStorage.setItem(TOKEN_STORAGE_KEY, tokenFromUrl));
    window.history.replaceState(
      window.history.state,
      '',
      window.location.pathname + window.location.search
    );
    return tokenFromUrl;
  }

  return stored(() => localStorage.getItem(TOKEN_STORAGE_KEY))
    || stored(() => sessionStorage.getItem(TOKEN_STORAGE_KEY))
    || '';
}

export function forgetToken() {
  stored(() => localStorage.removeItem(TOKEN_STORAGE_KEY));
  stored(() => sessionStorage.removeItem(TOKEN_STORAGE_KEY));
}

const dashboardToken = getDashboardToken();
const authHeaders = () => dashboardToken
  ? { Authorization: `Bearer ${dashboardToken}` }
  : {};

// Payment history is only the dashboard's to read, so reads carry its token.
const NEEDS_LINK = "This screen can't show payments. Open the dashboard using its authorized link.";

async function getSnapshot() {
  const response = await fetch(`${API}/events?since=0`, {
    cache: 'no-store',
    headers: authHeaders(),
  });
  if (response.status === 401) throw new Error(NEEDS_LINK);
  if (!response.ok) throw new Error(`Couldn't load activity (HTTP ${response.status})`);
  const rows = await response.json();
  if (!Array.isArray(rows)) throw new Error('Unexpected /events response');
  return rows;
}

async function readEventStream(lastEventId, onEvent, onConnected, signal) {
  const response = await fetch(`${API}/stream`, {
    cache: 'no-store',
    headers: { ...authHeaders(), 'Last-Event-ID': String(lastEventId) },
    signal,
  });
  if (response.status === 401) throw new Error(NEEDS_LINK);
  if (!response.ok) throw new Error(`Live updates unavailable (HTTP ${response.status})`);
  if (!response.body) throw new Error('Live updates are not supported by this browser');
  onConnected();

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value, { stream: !done });
    let boundary;
    while ((boundary = buffer.search(/\r?\n\r?\n/)) !== -1) {
      const separator = buffer.slice(boundary).match(/^\r?\n\r?\n/)[0];
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + separator.length);
      const data = block.split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''))
        .join('\n');
      if (data) onEvent(JSON.parse(data));
    }
    if (done) return;
  }
}

// Full snapshots expose updates to older IDs, such as a decision resolving a hold.
export function useGuardEvents() {
  const [rowsById, setRowsById] = useState({});
  const [connection, setConnection] = useState('connecting');
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);
  const [demoBusy, setDemoBusy] = useState(null);
  const [limits, setLimits] = useState(null); // GET /limits; null until it answers
  const [role, setRole] = useState(null);
  const alive = useRef(true);

  const mergeEvent = useCallback((event) => {
    if (!event || !Number.isSafeInteger(event.event_id)) return;
    setRowsById((prev) => ({ ...prev, [event.event_id]: event }));
  }, []);

  const refresh = useCallback(async () => {
    const snapshot = await getSnapshot();
    if (alive.current) {
      setRowsById(Object.fromEntries(snapshot.map((event) => [event.event_id, event])));
      setError('');
    }
    return snapshot;
  }, []);

  useEffect(() => {
    alive.current = true;
    let disposed = false;
    const controller = new AbortController();

    async function pollOnce() {
      try {
        await refresh();
        if (!disposed) setConnection('polling');
      } catch (reason) {
        if (!disposed) {
          setConnection('offline');
          if (reason.message === NEEDS_LINK) setError(NEEDS_LINK);
        }
      }
    }

    async function start() {
      let lastEventId = 0;
      try {
        const identityResponse = await fetch(`${API}/whoami`, {
          cache: 'no-store',
          headers: authHeaders(),
        });
        let currentRole;
        if (identityResponse.status === 404) {
          currentRole = dashboardToken ? 'approver' : 'viewer';
        } else {
          if (!identityResponse.ok) {
            // A token from an earlier run of the guard: drop it, so the next
            // open of the printed link starts clean.
            if (identityResponse.status === 401) forgetToken();
            throw new Error(identityResponse.status === 401
              ? 'This screen needs the dashboard link the guard printed. Open it once on this device.'
              : `Dashboard access denied (HTTP ${identityResponse.status})`);
          }
          currentRole = (await identityResponse.json()).role;
        }
        if (!disposed) setRole(currentRole);
        const snapshot = await refresh();
        lastEventId = snapshot.reduce(
          (maxId, event) => Math.max(maxId, event.event_id), 0
        );
      } catch (reason) {
        if (!disposed) {
          setError(reason.message || 'Dashboard access failed');
          setConnection('offline');
        }
        return;
      }

      while (!disposed) {
        try {
          await readEventStream(
            lastEventId,
            (event) => {
              mergeEvent(event);
              lastEventId = Math.max(lastEventId, event.event_id);
            },
            () => { if (!disposed) setConnection('live'); },
            controller.signal,
          );
          if (!disposed) throw new Error('Live connection closed');
        } catch (reason) {
          if (disposed || reason.name === 'AbortError') return;
          if (reason.message === NEEDS_LINK) setError(NEEDS_LINK);
          setConnection('polling');
          await pollOnce();
          await new Promise((resolve) => window.setTimeout(resolve, 1800));
        }
      }
    }

    start();
    fetch(`${API}/limits`, { cache: 'no-store', headers: authHeaders() })
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => { if (!disposed && body) setLimits(body); })
      .catch(() => { /* keep the fallback limits */ });
    return () => {
      disposed = true;
      alive.current = false;
      controller.abort();
    };
  }, [refresh, mergeEvent]);

  async function override(event, action) {
    if (!['approver', 'admin'].includes(role) || event.status !== 'held' || busyId !== null) return;
    setBusyId(event.event_id);
    setError('');
    try {
      if (!dashboardToken) {
        throw new Error(
          'Dashboard authorization is missing. Open the dashboard using its authorized link.'
        );
      }

      const response = await fetch(`${API}/override`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${dashboardToken}`,
        },
        body: JSON.stringify({
          event_id: event.event_id,
          action,
        }),
      });
      if (!response.ok) {
        const details = await response.json().catch(() => null);
        throw new Error(details?.error || `HTTP ${response.status}`);
      }
      // The fake API returns the updated event. The frozen contract does not
      // mandate a response shape, so also refresh the complete snapshot.
      const changed = await response.json().catch(() => null);
      if (changed?.event_id === event.event_id) mergeEvent(changed);
      await refresh();
      return true;
    } catch (reason) {
      setError(`Couldn't ${action} payment: ${reason.message}`);
      return false;
    } finally {
      setBusyId(null);
    }
  }
  
  async function runDemo(scenario) {
    if (!['approver', 'admin'].includes(role)) {
      setError('Dashboard authorization is required to run simulations.');
      return false;
    }

    if (demoBusy !== null) return false;

    setDemoBusy(scenario);
    setError('');

    try {
      const response = await fetch(`${API}/demo/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${dashboardToken}`,
        },
        body: JSON.stringify({ scenario }),
      });

      if (!response.ok) {
        const details = await response.json().catch(() => null);
        throw new Error(details?.error || `HTTP ${response.status}`);
      }

      return true;
    } catch (err) {
      setError(`Couldn't start simulation: ${err.message}`);
      return false;
    } finally {
      setDemoBusy(null);
    }
  }

  const events = Object.values(rowsById).sort((a, b) => a.event_id - b.event_id);
  const canApprove = ['approver', 'admin'].includes(role);
  return {events, connection, error, busyId, override, runDemo, demoBusy,
    canApprove, canRunDemo: canApprove, limits };
}

const ANCHOR_KEY = 'accrue_record_anchor';

// Checks the guard's record with GET /verify every few seconds and after new
// activity. The last fingerprint (head) that checked out is kept in this tab
// and sent back as the anchor: rewriting the history and recomputing every
// fingerprint after it still won't match what this screen already saw.
// Per tab (sessionStorage), so a guard restarted with a fresh record for the
// demo isn't reported as tampered in a new tab.
export function useVerify(activityKey) {
  const [result, setResult] = useState(null);
  const [checkedAt, setCheckedAt] = useState(null);

  useEffect(() => {
    let disposed = false;
    async function check() {
      let anchor = null;
      try { anchor = JSON.parse(sessionStorage.getItem(ANCHOR_KEY) || 'null'); } catch { /* none */ }
      const query = anchor && Number.isSafeInteger(anchor.event_id) && typeof anchor.row_hash === 'string'
        ? `?anchor_id=${anchor.event_id}&anchor_hash=${encodeURIComponent(anchor.row_hash)}`
        : '';
      try {
        const response = await fetch(`${API}/verify${query}`, {
          cache: 'no-store',
          headers: authHeaders(),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const body = await response.json();
        if (disposed) return;
        setResult(body);
        setCheckedAt(new Date());
        if (body.ok && body.head) {
          try { sessionStorage.setItem(ANCHOR_KEY, JSON.stringify(body.head)); } catch { /* best effort */ }
        }
      } catch {
        if (!disposed) setResult(null);
      }
    }
    check();
    const timer = window.setInterval(check, 5000);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [activityKey]);

  return { result, checkedAt };
}
