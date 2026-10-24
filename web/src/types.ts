export type Mode = 'live' | 'drill' | 'replay'
export type RangeKey = '15m' | '1h' | 'today' | 'drill'
export type StreamState = 'connecting' | 'live' | 'polling' | 'replay'
export type Tone = 'danger' | 'warn' | 'ok' | 'info' | 'neutral' | 'accent'
export type LaneId = 'input' | 'decision' | 'behavior' | 'alert'

export interface AsiItem {
  id: string
  name: string
  level: 'full' | 'partial' | 'none'
  rules?: string[]
  note?: string
}

export interface ToolBaseline {
  status: string
  tools: number
  expected?: number
  label: string
  names?: string[]
}

export interface AgentRow {
  id?: string
  alias: string
  role?: string
  state: string
  model: string
  toolBaseline: ToolBaseline
  alerts: number
}

export interface ChainSummary {
  chainId?: string
  chainAlias?: string
  agentId?: string
  agentAlias?: string
  role?: string
  phase?: string
  confidence?: string
  rules: string[]
  alertCount?: number
  lastAt?: number
  dataset?: string
}

export interface TimelineBucket {
  start: number
  end: number
  label: string
  decision: number
  behavior: number
}

export interface Overview {
  version?: string
  dataset: 'live' | 'replay'
  publicSummary?: boolean
  range?: string
  since?: number
  until?: number
  serverTime?: number
  kernelBlock?: boolean
  label?: string
  note?: string
  sources: { online: number; degraded: number; offline: number; total: number }
  agents: { total: number; modelLinked: number }
  alerts: { total: number; high: number; medium: number; low: number; inChains: number }
  s03: { confirmed: number; total: number; p50HostSeconds: number | null }
  timeline: TimelineBucket[]
  topRules: { rule: string; name: string; count: number }[]
  agentRows: AgentRow[]
  recentChains: ChainSummary[]
  asi: AsiItem[]
  inactiveRules?: { id: string; name?: string; reason: string }[]
  coverageNote?: string
}

export interface SwimEvent {
  id: string
  t: number
  lane: LaneId
  row?: number
  title: string
  sub: string
  w?: number
  kind?: 'untrusted' | 'risky' | 'alert'
  onlyConfirmed?: boolean
  confirmedTitle?: string
  confirmedSub?: string
  eventId?: string
  drawer?: Record<string, unknown>
}

export interface SwimEdge {
  from: string
  to: string
  label: string
  onlyConfirmed?: boolean
  dashed?: boolean
}

export interface ChainFile {
  path: string
  before: string | null
  after: string | null
  rule: string
}

export interface ChainDetail {
  chainId: string
  agentId?: string
  agentAlias?: string
  role?: string
  phase?: string
  confidence?: string
  basis?: string
  semanticAt?: number | null
  confirmedAt?: number | null
  spanSeconds?: number
  latency?: { semanticSeconds?: number | null; hostSeconds?: number | null }
  dataset?: string
  publicSummary?: boolean
  events: SwimEvent[]
  edges: SwimEdge[]
  files: ChainFile[]
  alerts: AlertItem[]
}

export interface AlertItem {
  id: string
  rule: string
  ruleName?: string
  severity: string
  status?: string
  createdAt?: number
  count?: number
  phase?: string
  layer?: string
  chainId?: string
  agentId?: string
  agentAlias?: string
  title?: string
  confidence?: string
}

export interface AlertPage {
  items: AlertItem[]
  total: number
  publicSummary?: boolean
  note?: string
  coverageSummary?: { online: number; degraded: number; offline: number }
  inactiveRules?: { id: string; name?: string; reason: string }[]
  groups?: { key: string; count: number }[] | null
  serverTime?: number
}

export interface DrillRate {
  rate: number | null
  belowTarget: boolean
  detail: string
  label: string
}

export interface DrillMatch {
  alertId: string
  chainId?: string
  rule: string
  command?: string | null
}

export interface DrillRow {
  id: string
  action: string
  expected: string
  result: string
  tone: 'success' | 'warning' | 'danger' | 'neutral'
  latency: string
  cohort: string
  note?: string
  matches?: DrillMatch[]
}

export interface DrillReport {
  dataset?: string
  publicSummary?: boolean
  hidden?: boolean
  label?: string
  note?: string
  target?: number
  rates: { p0: DrillRate; s02: DrillRate; s03: DrillRate; fresh: DrillRate }
  rows: DrillRow[]
}

export interface CoverageReport {
  dataset?: string
  publicSummary?: boolean
  kernelBlock?: boolean
  serverTime?: number
  sources: { online: number; degraded: number; offline: number; total: number }
  recentLoss?: boolean
  gapCount?: number
  inactiveRules?: { id: string; name?: string; reason: string }[]
  note?: string
  sourceDetails?: {
    source?: string
    state?: string
    ageSeconds?: number
    degraded?: boolean
    layers?: Record<string, string>
    recentLoss?: { total?: number | null }
    gaps?: { start?: number; end?: number | null }[]
    host?: string
    lossWarning?: string | null
    limitations?: string[]
  }[]
}

export interface Me {
  role: string
  name: string
}

export interface ReplayFile {
  note?: string
  overview: Overview
  chains: ChainDetail[]
  alerts: AlertItem[]
  agents: AgentRow[]
  coverage: CoverageReport
  drill: DrillReport
}

export interface AlertFilters {
  rule: string
  severity: string
  phase: string
  layer: string
  agentId: string
  chainId: string
  since: string
  until: string
  group: string
}
