// Shared API health-check banner for playground and quick-start pages.
// Pings /api/health on load, shows a status banner, and auto-retries
// until the server responds (handles Render free-tier cold starts).

const API_BASE_URL =
  (import.meta as any).env?.PUBLIC_API_URL || 'https://zk-id-1.onrender.com';

type Status = 'checking' | 'online' | 'waking' | 'offline';

const RETRY_INTERVAL_MS = 5_000;
const MAX_RETRIES = 24; // ~2 minutes of retries

let retryCount = 0;
let retryTimer: ReturnType<typeof setTimeout> | null = null;

function getBanner(): HTMLElement | null {
  return document.getElementById('api-status-banner');
}

function render(status: Status) {
  const banner = getBanner();
  if (!banner) return;

  banner.removeAttribute('hidden');

  switch (status) {
    case 'checking':
      banner.className = 'api-status-banner status-checking';
      banner.innerHTML =
        '<span class="status-dot pulsing"></span> Checking API server status\u2026';
      break;

    case 'online':
      banner.className = 'api-status-banner status-online';
      banner.innerHTML =
        '<span class="status-dot"></span> API server is online';
      // Auto-hide after 3 seconds
      setTimeout(() => {
        banner.setAttribute('hidden', '');
      }, 3_000);
      break;

    case 'waking':
      banner.className = 'api-status-banner status-waking';
      banner.innerHTML =
        '<span class="status-dot pulsing"></span> API server is waking up \u2014 free-tier cold starts can take up to 60 seconds\u2026';
      break;

    case 'offline':
      banner.className = 'api-status-banner status-offline';
      banner.innerHTML =
        '<span class="status-dot"></span> API server is unavailable. <button class="retry-link" id="api-retry-btn">Retry</button>';
      document.getElementById('api-retry-btn')?.addEventListener('click', () => {
        retryCount = 0;
        checkHealth();
      });
      break;
  }
}

async function checkHealth(): Promise<void> {
  render(retryCount === 0 ? 'checking' : 'waking');

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    const res = await fetch(`${API_BASE_URL}/api/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.ok) {
      render('online');
      return;
    }
    scheduleRetry();
  } catch {
    scheduleRetry();
  }
}

function scheduleRetry() {
  retryCount++;
  if (retryCount >= MAX_RETRIES) {
    render('offline');
    return;
  }
  render('waking');
  retryTimer = setTimeout(checkHealth, RETRY_INTERVAL_MS);
}

export function initApiStatus() {
  document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
  });
}

// Auto-initialize when imported
initApiStatus();
