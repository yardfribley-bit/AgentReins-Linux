import { useMemo, useState } from 'react'
import type { SwimEdge, SwimEvent } from './types'

const left = 132
const right = 1180
const rowH = 42
const pad = 10
const top = 44
const colors = { alert: '#ff5d52', untrusted: '#f0b429', edge: '#8eb6ff', text: '#edf2f7', muted: '#93a4b8', faint: '#6d8096', line: '#243140', card: '#10151c', band: 'rgba(240,180,41,0.08)' }

function widthOf(event: SwimEvent) {
  if (event.w) return event.w
  const chars = Math.max(event.title.length, Math.min(event.sub.length, 36))
  return Math.max(168, Math.min(420, chars * 8 + 36))
}

function place(events: SwimEvent[]) {
  const explicit = events.length > 0 && events.every((event) => Number.isInteger(event.row))
  if (explicit) return events.map((event) => ({ ...event, row: event.row ?? 0 }))
  const lanes: Record<string, number[]> = {}
  return events.map((event) => {
    const ends = lanes[event.lane] || (lanes[event.lane] = [])
    let row = ends.findIndex((end) => event.t >= end)
    if (row < 0) {
      row = ends.length
      ends.push(event.t + 0.9)
    } else ends[row] = event.t + 0.9
    return { ...event, row }
  })
}

const lanes = [
  { id: 'input', name: '输入层', hint: '模型收到什么' },
  { id: 'decision', name: '决策层', hint: '模型想做什么' },
  { id: 'behavior', name: '行为层', hint: '主机实际做了什么' },
  { id: 'alert', name: '告警', hint: 'S03 两段 / S02 / S01 / S08' },
] as const

export function Swimlane({
  events,
  edges,
  spanSeconds,
  semanticAt,
  confirmedAt,
  stage,
  onSelect,
}: {
  events: SwimEvent[]
  edges: SwimEdge[]
  spanSeconds?: number
  semanticAt?: number | null
  confirmedAt?: number | null
  stage: 'semantic' | 'confirmed'
  onSelect: (event: SwimEvent) => void
}) {
  const placed = useMemo(() => place(events), [events])
  const span = Math.max(spanSeconds || 0, ...placed.map((event) => event.t), 1)
  const rows: Record<string, number> = {}
  for (const lane of lanes) {
    const used = placed.filter((event) => event.lane === lane.id).map((event) => event.row)
    rows[lane.id] = used.length ? Math.max(...used) + 1 : 1
  }
  const laneTop: Record<string, number> = {}
  let y = top
  for (const lane of lanes) {
    laneTop[lane.id] = y
    y += rows[lane.id] * rowH + pad * 2
  }
  const bottom = y
  const xOf = (t: number) => left + (t / span) * (right - left)
  const pos = (id: string) => {
    const event = placed.find((item) => item.id === id)
    if (!event) return null
    return { x: xOf(event.t), y: laneTop[event.lane] + pad + event.row * rowH, w: widthOf(event), h: 34, event }
  }
  const bandStart = placed.find((event) => event.kind === 'untrusted')?.t ?? semanticAt ?? 0
  const ticks = [0, span / 4, span / 2, (span * 3) / 4, span]
  const [hover, setHover] = useState<string | null>(null)

  return (
    <div className="overflow-x-auto">
      <svg width="100%" viewBox={`0 0 1240 ${bottom + 8}`} role="img" aria-label="调用链泳道" className="min-w-[880px]">
        <rect x={xOf(bandStart)} y={top} width={Math.max(0, 1230 - xOf(bandStart))} height={bottom - top} fill={colors.band} />
        <text x={xOf(bandStart) + 6} y={top - 8} fontSize="11" fill={colors.muted}>不受信片段进入链路之后（向前回看 3600 s）</text>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={xOf(tick)} x2={xOf(tick)} y1={top} y2={bottom} stroke={colors.line} />
            <text x={xOf(tick)} y={20} fontSize="11" fill={colors.faint} textAnchor="middle">{`${tick.toFixed(tick >= 10 ? 0 : 1)} s`}</text>
          </g>
        ))}
        {lanes.map((lane) => (
          <g key={lane.id}>
            <line x1={0} x2={1240} y1={laneTop[lane.id]} y2={laneTop[lane.id]} stroke={colors.line} />
            <text x={8} y={laneTop[lane.id] + 26} fontSize="13" fontWeight={600} fill={colors.text}>{lane.name}</text>
            <text x={8} y={laneTop[lane.id] + 44} fontSize="11" fill={colors.faint}>{lane.hint}</text>
          </g>
        ))}
        <line x1={0} x2={1240} y1={bottom} y2={bottom} stroke={colors.line} />
        {semanticAt != null && <line x1={xOf(semanticAt)} x2={xOf(semanticAt)} y1={top} y2={bottom} stroke={colors.alert} strokeDasharray="3 3" />}
        {stage === 'confirmed' && confirmedAt != null && <line x1={xOf(confirmedAt)} x2={xOf(confirmedAt)} y1={top} y2={bottom} stroke={colors.alert} strokeDasharray="3 3" />}
        {edges.map((edge) => {
          const from = pos(edge.from)
          const to = pos(edge.to)
          if (!from || !to) return null
          const x1 = from.x + 40
          const y1 = from.y + from.h
          const x2 = to.x + 30
          const y2 = to.y
          const mid = (y1 + y2) / 2
          const dim = edge.onlyConfirmed && stage === 'semantic'
          return (
            <g key={edge.from + edge.to} opacity={dim ? 0.15 : 1}>
              <path d={`M${x1},${y1} C${x1},${mid} ${x2},${mid} ${x2},${y2}`} fill="none" stroke={colors.edge} strokeWidth={1.5} strokeDasharray={edge.dashed ? '5 4' : undefined} />
              <text x={x2 + 8} y={y2 - 6} fontSize="11" fill={colors.muted}>{edge.label}</text>
            </g>
          )
        })}
        {placed.map((event) => {
          const box = pos(event.id)
          if (!box) return null
          const clip = 'c-' + event.id.replace(/[^A-Za-z0-9_-]/g, '')
          const dim = stage === 'semantic' && (event.onlyConfirmed || (event.lane === 'behavior' && semanticAt != null && event.t > semanticAt))
          const title = stage === 'confirmed' && event.confirmedTitle ? event.confirmedTitle : event.title
          const sub = stage === 'confirmed' && event.confirmedSub ? event.confirmedSub : event.sub
          const stroke = event.kind === 'untrusted' ? colors.untrusted : event.kind === 'risky' || event.kind === 'alert' ? colors.alert : colors.line
          return (
            <g key={event.id} opacity={dim ? 0.18 : hover === event.id ? 1 : 0.96} className="cursor-pointer" onClick={() => onSelect(event)} onMouseEnter={() => setHover(event.id)} onMouseLeave={() => setHover(null)}>
              <clipPath id={clip}>
                <rect x={box.x + 4} y={box.y} width={box.w - 8} height={box.h} />
              </clipPath>
              <rect x={box.x} y={box.y} width={box.w} height={box.h} rx={6} fill={colors.card} stroke={stroke} strokeWidth={event.kind ? 2 : 1} />
              {event.kind === 'alert' && <rect x={box.x + 8} y={box.y + 8} width={7} height={7} transform={`rotate(45 ${box.x + 11.5} ${box.y + 11.5})`} fill={colors.alert} />}
              <text clipPath={`url(#${clip})`} x={box.x + (event.kind === 'alert' ? 22 : 8)} y={box.y + 14} fontSize="11" fontWeight={600} fill={colors.text}>{title}</text>
              <text clipPath={`url(#${clip})`} x={box.x + 8} y={box.y + 28} fontSize="10" fill={colors.muted} fontFamily="IBM Plex Mono, ui-monospace, monospace">{sub}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
