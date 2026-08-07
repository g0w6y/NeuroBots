import { useCallback, useEffect, useState } from 'react';

// One-shot fetch with an explicit refresh, for gateway data that does not change
// on a 2-second cadence: the route table (fixed at gateway startup) and the
// ownership grants (only change when someone provisions one).
//
// Deliberately NOT folded into useLiveData's poll loop. That loop refetches four
// endpoints every 2s; adding two more that almost never change would double the
// request volume for no new information.
//
// state is 'loading' | 'ready' | 'error'. On error the last good `data` is kept
// rather than blanked - same principle the live poll uses, since showing stale
// real data beats showing nothing.
export function useResource(fetcher, { auto = true } = {}) {
  const [data, setData] = useState(null);
  const [state, setState] = useState(auto ? 'loading' : 'idle');
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setState((s) => (s === 'idle' ? 'loading' : s));
    try {
      const result = await fetcher();
      setData(result);
      setState('ready');
      setError(null);
      return result;
    } catch (e) {
      setState('error');
      setError(
        e?.response?.status === 401
          ? 'admin key rejected (401) — VITE_ADMIN_KEY must match the gateway ADMIN_API_KEY'
          : e?.message || 'gateway unreachable'
      );
      return null;
    }
    // fetcher is expected to be a stable module-level function; listing it here
    // would re-create refresh on every render for callers passing an inline
    // arrow, which then re-fires the effect below in a loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (auto) refresh();
  }, [auto, refresh]);

  return { data, state, error, refresh };
}
