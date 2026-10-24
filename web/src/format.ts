export function formatTime(value?: number | null) {
  if (value == null || Number.isNaN(value)) return '—'
  const date = new Date(value * 1000)
  const pad = (n: number, size = 2) => String(n).padStart(size, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`
}

export function formatSeconds(value?: number | null) {
  if (value == null || Number.isNaN(value)) return '—'
  return `${value.toFixed(value >= 10 ? 1 : 2)} s`
}

export function hostDelayDetail(value?: number | null) {
  if (value == null || Number.isNaN(value)) return '确认延迟 P50 —'
  if (value < 0) return `主机时间超前 P50 ${formatSeconds(-value)}`
  return `确认延迟 P50 ${formatSeconds(value)}`
}

export function delayPhrase(label: string, ahead: string, value?: number | null) {
  if (value == null || Number.isNaN(value)) return `${label} —`
  if (value < 0) return `${ahead} ${formatSeconds(-value)}`
  return `${label} ${formatSeconds(value)}`
}

export function severityLabel(value?: string) {
  if (value === 'high') return '高'
  if (value === 'medium') return '中'
  if (value === 'low') return '低'
  return value || '—'
}

export function layerLabel(value?: string) {
  if (value === 'D') return '决策层'
  if (value === 'B') return '行为层'
  return value || '—'
}

export function stateLabel(value?: string) {
  if (value === 'online') return 'online'
  if (value === 'degraded') return 'degraded'
  if (value === 'offline') return 'offline'
  return value || 'unknown'
}

export function modelLabel(value?: string) {
  if (value === 'linked') return 'linked'
  if (value === 'gateway_bound') return 'gateway_bound'
  if (value === 'gateway_unbound') return 'gateway_unbound'
  if (value === 'not_connected') return 'not_connected'
  return value || '—'
}

export function renderValue(value: unknown) {
  if (value == null || value === '') return '—'
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}
