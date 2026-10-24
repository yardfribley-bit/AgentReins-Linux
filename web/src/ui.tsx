import * as Dialog from '@radix-ui/react-dialog'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import * as Tooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'
import { useState } from 'react'
import { getMe } from './api'
import { useSession } from './session'
import type { AsiItem, Mode, RangeKey, Tone } from './types'

const toneClass: Record<Tone, string> = {
  danger: 'border-signal/50 bg-signal/15 text-signal',
  warn: 'border-amber/50 bg-amber/15 text-amber',
  ok: 'border-ok/40 bg-ok/15 text-ok',
  info: 'border-info/40 bg-info/15 text-info',
  neutral: 'border-line-strong bg-panel-2 text-muted',
  accent: 'border-sea/40 bg-sea/15 text-sea',
}

export function Badge({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] leading-4 font-medium ${toneClass[tone]}`}>{children}</span>
}

export function SeverityBadge({ value }: { value?: string }) {
  const tone: Tone = value === 'high' ? 'danger' : value === 'medium' ? 'warn' : 'neutral'
  const label = value === 'high' ? '高' : value === 'medium' ? '中' : value === 'low' ? '低' : value || '—'
  return <Badge tone={tone}>{label}</Badge>
}

export function PhaseBadge({ value }: { value?: string }) {
  if (!value) return <Badge>无阶段</Badge>
  if (value === 'host_confirmed') return <Badge tone="accent">host_confirmed</Badge>
  if (value === 'semantic') return <Badge>semantic</Badge>
  return <Badge>{value}</Badge>
}

export function ConfidenceBadge({ value }: { value?: string }) {
  if (!value) return null
  const tone: Tone = value === 'observed' ? 'ok' : value === 'correlated' ? 'info' : value === 'inferred' ? 'warn' : 'neutral'
  return <Badge tone={tone}>{value}</Badge>
}

export function LayerBadge({ value }: { value?: string }) {
  if (value === 'D') return <Badge tone="info">决策层</Badge>
  if (value === 'B') return <Badge tone="accent">行为层</Badge>
  return value ? <Badge>{value}</Badge> : null
}

export function StateBadge({ value }: { value?: string }) {
  const tone: Tone = value === 'online' ? 'ok' : value === 'degraded' ? 'warn' : value === 'offline' ? 'danger' : 'neutral'
  return <Badge tone={tone}>{value || 'unknown'}</Badge>
}

export function Panel({ title, extra, children, className = '' }: { title?: string; extra?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-panel ${className}`}>
      {(title || extra) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold tracking-wide">{title}</h2>
          {extra}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Metric({ value, label, detail }: { value: string; label: string; detail: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="text-[11px] tracking-wider text-faint uppercase">{label}</div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-ink-text">{value}</div>
      <div className="mt-1 text-xs text-muted">{detail}</div>
    </div>
  )
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line-strong bg-panel-2 px-4 py-6 text-sm text-muted">
      <p className="font-medium text-ink-text">{title}</p>
      {children && <div className="mt-2 space-y-1">{children}</div>}
    </div>
  )
}

export function AsiStrip({ items }: { items: AsiItem[] }) {
  const width = 86
  const gap = 6
  const full = items.filter((item) => item.level === 'full').length
  const partial = items.filter((item) => item.level === 'partial').length
  const none = items.filter((item) => item.level === 'none').length
  return (
    <svg width="100%" viewBox={`0 0 ${items.length * (width + gap)} 128`} role="img" aria-label="OWASP ASI 覆盖条">
      {items.map((item, index) => {
        const x = index * (width + gap)
        const fill = item.level === 'full' ? '#ff5d52' : item.level === 'partial' ? 'rgba(255,93,82,0.28)' : 'none'
        return (
          <g key={item.id}>
            <title>{`${item.id} ${item.name}`}</title>
            <rect x={x} y={8} width={width} height={44} rx={6} fill={fill} stroke={item.level === 'none' ? '#3c5168' : '#ff5d52'} />
            <text x={x + width / 2} y={74} textAnchor="middle" fill="#edf2f7" fontSize="11" fontFamily="IBM Plex Mono, ui-monospace, monospace">{item.id.replace('ASI', '')}</text>
            <text x={x + width / 2} y={94} textAnchor="middle" fill="#6d8096" fontSize="10" fontFamily="IBM Plex Sans, sans-serif">{item.name}</text>
          </g>
        )
      })}
      <text x={0} y={118} fill="#93a4b8" fontSize="11" fontFamily="IBM Plex Sans, sans-serif">{`实心 = 覆盖 ${full} 项 · 浅色 = 部分覆盖 ${partial} 项 · 空框 = 未覆盖 ${none} 项（只检测，不预防）`}</text>
    </svg>
  )
}

export function RuleBars({ rows }: { rows: { rule: string; name: string; count: number }[] }) {
  const max = Math.max(1, ...rows.map((row) => row.count))
  if (!rows.length) return <EmptyState title="这个窗口没有命中规则。" />
  return (
    <div className="space-y-2.5">
      {rows.map((row, index) => (
        <div key={row.rule} className="grid grid-cols-[minmax(0,1fr)_2.5rem] items-center gap-3 text-sm">
          <div>
            <div className="mb-1 flex items-baseline justify-between gap-2">
              <span className="truncate"><span className="font-mono text-info">{row.rule}</span> <span className="text-muted">{row.name}</span></span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-panel-2">
              <div className={`h-full rounded-full ${index === 0 ? 'bg-signal' : 'bg-info/80'}`} style={{ width: `${(row.count / max) * 100}%` }} />
            </div>
          </div>
          <div className="text-right font-mono tabular-nums">{row.count}</div>
        </div>
      ))}
    </div>
  )
}

const ranges: { id: RangeKey; label: string }[] = [
  { id: '15m', label: '15 分钟' },
  { id: '1h', label: '1 小时' },
  { id: 'today', label: '今天' },
  { id: 'drill', label: '演练全程' },
]
const modes: { id: Mode; label: string }[] = [
  { id: 'live', label: '生产' },
  { id: 'drill', label: '演练' },
  { id: 'replay', label: '回放' },
]

export function TopBar() {
  const session = useSession()
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const streamLabel = session.stream === 'live' ? '实时' : session.stream === 'polling' ? '轮询' : session.stream === 'replay' ? '回放' : '连接中'
  const streamTone = session.stream === 'live' ? 'bg-ok' : session.stream === 'polling' ? 'bg-amber' : session.stream === 'replay' ? 'bg-info' : 'bg-faint'
  const identity = session.mode === 'replay' ? '公开回放' : session.role === 'operator' ? session.me?.name || '操作员' : session.role === 'referee' ? session.me?.name || '裁判' : '公开只读'

  async function submit() {
    setError('')
    try {
      const me = await getMe(draft.trim())
      if (me.role !== 'operator' && me.role !== 'referee') throw new Error('不是操作员或裁判凭证')
      session.setToken(draft.trim())
      setDraft('')
      setOpen(false)
    } catch (err) {
      session.setToken(null)
      setError(err instanceof Error ? err.message : '凭证无效')
    }
  }

  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-line bg-ink/90 px-4 py-3 backdrop-blur">
      <div className="mr-auto min-w-48">
        <div className="text-sm font-semibold tracking-wide">AgentReins 观测台</div>
        <div className="text-[11px] text-faint">只观测、只告警 · 不阻断、不回滚</div>
      </div>
      <div className="flex rounded-md border border-line p-0.5">
        {modes.map((item) => (
          <button key={item.id} type="button" className={`rounded px-2.5 py-1 text-xs ${session.mode === item.id ? 'bg-panel-2 text-ink-text' : 'text-muted'}`} onClick={() => session.setMode(item.id)}>{item.label}</button>
        ))}
      </div>
      <div className="flex rounded-md border border-line p-0.5">
        {ranges.map((item) => (
          <button key={item.id} type="button" disabled={session.mode === 'replay'} className={`rounded px-2.5 py-1 text-xs disabled:opacity-40 ${session.range === item.id ? 'bg-panel-2 text-ink-text' : 'text-muted'}`} onClick={() => session.setRange(item.id)}>{item.label}</button>
        ))}
      </div>
      <Tooltip.Provider delayDuration={200}>
        <Tooltip.Root>
          <Tooltip.Trigger asChild>
            <div className="flex items-center gap-2 text-xs text-muted">
              <span className={`pulse h-2 w-2 rounded-full ${streamTone}`} />
              {streamLabel}
            </div>
          </Tooltip.Trigger>
          <Tooltip.Portal>
            <Tooltip.Content className="rounded border border-line bg-panel-2 px-2 py-1 text-xs text-muted" sideOffset={6}>
              {session.stream === 'polling' ? 'SSE 断开，已改为 2 秒轮询' : session.stream === 'live' ? 'SSE 已连接，只推脱敏增量' : '当前不是线上流'}
            </Tooltip.Content>
          </Tooltip.Portal>
        </Tooltip.Root>
      </Tooltip.Provider>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger className="rounded-md border border-line px-2.5 py-1 text-xs text-muted">{identity}</DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="z-30 min-w-40 rounded-md border border-line bg-panel p-1 text-sm shadow-xl" align="end">
            <DropdownMenu.Item className="cursor-pointer rounded px-2 py-1.5 outline-none data-[highlighted]:bg-panel-2" onSelect={() => { session.setToken(null); setError('') }}>公开只读</DropdownMenu.Item>
            <DropdownMenu.Item className="cursor-pointer rounded px-2 py-1.5 outline-none data-[highlighted]:bg-panel-2" onSelect={() => setOpen(true)}>输入凭证</DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
      <Dialog.Root open={open} onOpenChange={setOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60" />
          <Dialog.Content className="fixed top-1/2 left-1/2 w-[min(420px,calc(100%-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-line bg-panel p-5">
            <Dialog.Title className="text-base font-semibold">操作员或裁判凭证</Dialog.Title>
            <Dialog.Description className="mt-1 text-xs text-muted">只放在页面内存里，刷新即清除。裁判可以看演练明细，不能处置、放行或加白。</Dialog.Description>
            <input className="mt-4 w-full rounded border border-line bg-ink px-3 py-2 font-mono text-sm outline-none" type="password" autoComplete="off" value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void submit() }} />
            {error && <p className="mt-2 text-xs text-signal">{error}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" className="rounded px-3 py-1.5 text-sm text-muted" onClick={() => setOpen(false)}>取消</button>
              <button type="button" className="rounded bg-ink-text px-3 py-1.5 text-sm text-ink" onClick={() => void submit()}>使用此凭证</button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </header>
  )
}

export function QueryNote({ error, loading }: { error: Error | null; loading: boolean }) {
  if (error) return <EmptyState title="读取失败">{error.message}</EmptyState>
  if (loading) return <p className="text-xs text-faint">正在读取…</p>
  return null
}
