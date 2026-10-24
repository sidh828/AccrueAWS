import { useCallback, useEffect, useRef, useState } from 'react';

const API = import.meta.env.VITE_API_BASE || '';

const TOKEN_STORAGE_KEY = 'accrue_dashboard_token';

// The demo backend prints a URL containing #token=...
// Read it from the URL without sending it in normal page requests.
function getDashboardToken() {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const tokenFromUrl = params.get('token');

  if (tokenFromUrl) {
    // Keep the token for this browser tab's session.
    sessionStorage.setItem(TOKEN_STORAGE_KEY, tokenFromUrl);

    // Remove the secret from the visible address bar.
    window.history.replaceState(
      window.history.state,
      '',
      window.location.pathname + window.location.search
    );

    return tokenFromUrl;
  }

  return sessionStorage.getItem(TOKEN_STORAGE_KEY) || '';
}

const dashboardToken = getDashboardToken();

async function getSnapshot() {
  const response = await fetch(`${API}/events?since=0`, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Couldn't load activity (HTTP ${response.status})`);
  const rows = await response.json();
  if (!Array.isArray(rows)) throw new Error('Unexpected /events response');
  return rows;
}

// Full snapshots are important: /events?since=lastId does not expose updates to older IDs.
// /stream sends changed rows, including an override that changes an old ID.
export function useGuardEvents() {
  const [rowsById, setRowsById] = useState({});
  const [connection, setConnection] = useState('connecting');
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);
  const [demoBusy, setDemoBusy] = useState(null);
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
    let source = null;
    let pollingTimer = null;
    let pollBusy = false;
    let disposed = false;

    async function pollOnce() {
      if (pollBusy || disposed) return;
      pollBusy = true;
      try {
        await refresh();
        if (!disposed) setConnection('polling');
      } catch {
        if (!disposed) setConnection('offline');
      } finally {
        pollBusy = false;
      }
    }

    function beginPolling() {
      if (pollingTimer || disposed) return;
      if (source) source.close();
      setConnection('polling');
      pollOnce();
      pollingTimer = window.setInterval(pollOnce, 1800);
    }

    async function start() {
      try {
        await refresh();
      } catch {
        if (!disposed) setConnection('offline');
      }
      if (disposed) return;

      // EventSource is a one-way read connection; approve/deny uses POST.
      // Fail over after the first SSE error, including a missing /stream endpoint.
      source = new EventSource(`${API}/stream`);
      source.onopen = () => { if (!disposed) setConnection('live'); };
      source.onmessage = (message) => {
        try { mergeEvent(JSON.parse(message.data)); } catch { /* Ignore invalid messages */ }
      };
      source.onerror = () => beginPolling();
    }

    start();
    return () => {
      disposed = true;
      alive.current = false;
      if (source) source.close();
      if (pollingTimer) window.clearInterval(pollingTimer);
    };
  }, [refresh, mergeEvent]);

  async function override(event, action) {
    if (event.status !== 'held' || busyId !== null) return;
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
    if (!dashboardToken) {
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
  return {events, connection, error, busyId, override, runDemo, demoBusy,canRunDemo: Boolean(dashboardToken),}; 
}
