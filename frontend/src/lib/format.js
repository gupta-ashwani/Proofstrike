/**
 * Shared formatting + posture helpers used across the target-centric pages.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// Matches the design-system severity tokens in styles/index.css.
export const SEVERITY_COLOR = {
  critical: '#C84010',
  high: '#C86618',
  medium: '#C88A28',
  low: '#555555',
  info: '#333333',
};

export const INTERVAL_PRESETS = [
  { label: 'Every 15 minutes', value: 15 },
  { label: 'Hourly', value: 60 },
  { label: 'Every 6 hours', value: 360 },
  { label: 'Daily', value: 1440 },
  { label: 'Weekly', value: 10080 },
];

// 90 -> "1h 30m", 1440 -> "Daily"
export function formatInterval(mins) {
  if (!mins) return '—';
  const preset = INTERVAL_PRESETS.find((p) => p.value === mins);
  if (preset) return preset.label;
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ');
}

// Relative time until a future ISO timestamp: "in 42m", "due now".
export function formatCountdown(iso) {
  if (!iso) return null;
  const secs = (new Date(iso).getTime() - Date.now()) / 1000;
  if (secs <= 30) return 'due now';
  if (secs < 3600) return `in ${Math.round(secs / 60)}m`;
  if (secs < 86400) return `in ${Math.round(secs / 3600)}h`;
  return `in ${Math.round(secs / 86400)}d`;
}

// Relative time since a past ISO timestamp: "2h ago", "just now".
export function formatAgo(iso) {
  if (!iso) return '—';
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  if (secs < 604800) return `${Math.round(secs / 86400)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export const ACTIVE_SCAN_STATUSES = ['queued', 'crawling', 'testing', 'verifying'];

export function isActiveStatus(status) {
  return ACTIVE_SCAN_STATUSES.includes((status || '').toLowerCase());
}
