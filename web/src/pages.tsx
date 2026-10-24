import * as Dialog from '@radix-ui/react-dialog'
import { useQuery } from '@tanstack/react-query'
import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ApiError, getJson } from './api'
import { delayPhrase, formatTime, hostDelayDetail, layerLabel, renderValue } from './format'
import { replay } from './replay'

const TimelineChart = lazy(() => import('./chart').then((mod) => ({ default: mod.TimelineChart })))
import { useSession } from './session'
import { Swimlane } from './swimlane'
import type { AlertFilters, AlertItem, AlertPage, ChainDetail, ChainSummary, CoverageReport, DrillReport, Overview, SwimEvent } from './types'
import { AsiStrip, Badge, ConfidenceBadge, EmptyState, LayerBadge, Metric, Panel, PhaseBadge, QueryNote, RuleBars, SeverityBadge, StateBadge } from './ui'

function useOverview() {
  const session = useSession()
  return useQuery({
    queryKey: ['overview', session.mode, session.range, session.gen, session.evidence],
    queryFn: () => {
      if (session.mode === 'replay') return Promise.resolve(replay.overview)
      const range = session.mode === 'drill' && session.range === '1h' ? 'drill' : session.range
      return getJson<Overview>(`/runtime/api/v2/overview?range=${range}`, session.tokenRef.current)
    },
    refetchInterval: session.mode !== 'replay' && session.stream !== 'live' ? 2000 : false,
  })
}

export function OverviewPage() {
  const query = useOverview()
  const data = query.data
  const navigate = useNavigate()
  const s03 = data && data.s03.total ? `${data.s03.confirmed}/${data.s03.total}` : '0/0'
  return (
    <div className="space-y-4">
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {data && (
        <>
          <p className="text-sm text-muted">
            {data.note || `窗口内 ${data.alerts.total} 条告警，其中 ${data.alerts.inChains} 条进入了调用链。`}
            {data.dataset === 'replay' ? ' 这是事先脱敏的回放，不随时间范围改变。' : ''}
          </p>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Metric value={`${data.sources.online}/${data.sources.total || 0}`} label="在线采集源" detail={`降级 ${data.sources.degraded}`} />
            <Metric value={String(data.agents.total)} label="已接入 Agent" detail={`模型层 linked ${data.agents.modelLinked}`} />
            <Metric value={String(data.alerts.total)} label="窗口内告警" detail={`高 ${data.alerts.high} · 中 ${data.alerts.medium} · 低 ${data.alerts.low}`} />
            <Metric value={s03} label="S03 主机确认" detail={hostDelayDetail(data.s03.p50HostSeconds)} />
          </div>
          <div className="grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.8fr)]">
            <Panel title="告警随时间 · 按层叠加" extra={<span className="text-[11px] text-faint">点击柱子进入告警中心</span>}>
              {data.alerts.total === 0 ? <EmptyState title="这个窗口没有告警。">{data.coverageNote}</EmptyState> : (
                <Suspense fallback={<p className="text-xs text-faint">正在读取图表…</p>}>
                  <TimelineChart buckets={data.timeline} onPick={(bucket, layer) => navigate(`/alerts?since=${bucket.start}&until=${bucket.end}&layer=${layer}`)} />
                </Suspense>
              )}
            </Panel>
            <Panel title="命中最多的规则">
              <RuleBars rows={data.topRules} />
            </Panel>
          </div>
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel title="Agent">
              <AgentTable rows={data.agentRows} />
            </Panel>
            <Panel title="OWASP 智能体 Top 10 覆盖">
              <AsiStrip items={data.asi} />
              <div className="mt-3 space-y-2">
                {data.recentChains.map((chain) => <ChainLink key={chain.chainId || chain.chainAlias} chain={chain} />)}
                {!data.recentChains.length && <EmptyState title="还没有调用链。">{data.publicSummary ? '匿名看不到线上链路，可以切换到回放。' : '新的链会出现在这里。'}</EmptyState>}
              </div>
            </Panel>
          </div>
          {data.alerts.total === 0 && <InactiveRules rules={data.inactiveRules} note={data.coverageNote} />}
        </>
      )}
    </div>
  )
}

function AgentTable({ rows }: { rows: Overview['agentRows'] }) {
  if (!rows.length) return <EmptyState title="还没有 Agent。">心跳里的路由，或带 agentId 的事件，会出现在这里。</EmptyState>
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-[11px] tracking-wide text-faint uppercase">
          <tr><th className="py-1 pr-3 font-medium">Agent</th><th className="py-1 pr-3 font-medium">角色</th><th className="py-1 pr-3 font-medium">采集</th><th className="py-1 pr-3 font-medium">模型层</th><th className="py-1 pr-3 font-medium">工具基线</th><th className="py-1 font-medium">告警</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id || row.alias} className="border-t border-line">
              <td className="py-2 pr-3 font-mono text-xs">{row.id || row.alias}</td>
              <td className="py-2 pr-3 text-muted">{row.role || '未标注'}</td>
              <td className="py-2 pr-3"><StateBadge value={row.state} /></td>
              <td className="py-2 pr-3 font-mono text-xs text-muted">{row.model}</td>
              <td className="py-2 pr-3 text-muted">{row.toolBaseline.label}</td>
              <td className="py-2 font-mono tabular-nums">{row.alerts}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ChainLink({ chain }: { chain: ChainSummary }) {
  const body = (
    <span className="flex items-center justify-between gap-3 rounded border border-line px-3 py-2 text-sm">
      <span className="font-mono text-xs">{chain.chainId || chain.chainAlias}</span>
      <span className="text-muted">{chain.agentId || chain.agentAlias}</span>
      <PhaseBadge value={chain.phase} />
      <span className="font-mono text-[11px] text-faint">{chain.rules.join(' ')}</span>
    </span>
  )
  if (!chain.chainId) return <div>{body}</div>
  return <Link to={`/chains/${chain.chainId}`} className="block hover:bg-panel-2">{body}</Link>
}

function InactiveRules({ rules, note }: { rules?: { id: string; name?: string; reason: string }[]; note?: string }) {
  if (!rules?.length && !note) return null
  return (
    <Panel title="没有告警时先看覆盖">
      <p className="mb-3 text-sm text-muted">{note}</p>
      <ul className="space-y-1 text-sm">
        {(rules || []).map((rule) => <li key={rule.id}><span className="font-mono text-info">{rule.id}</span> {rule.name} · {rule.reason}</li>)}
      </ul>
    </Panel>
  )
}

const emptyFilters: AlertFilters = { rule: '', severity: '', phase: '', layer: '', agentId: '', chainId: '', since: '', until: '', group: '' }

export function AlertsPage() {
  const session = useSession()
  const [params, setParams] = useSearchParams()
  const filters: AlertFilters = {
    ...emptyFilters,
    rule: params.get('rule') || '',
    severity: params.get('severity') || '',
    phase: params.get('phase') || '',
    layer: params.get('layer') || '',
    agentId: params.get('agentId') || '',
    chainId: params.get('chainId') || '',
    since: params.get('since') || '',
    until: params.get('until') || '',
    group: params.get('group') || '',
  }
  const setFilter = (key: keyof AlertFilters, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
  }
  const query = useQuery({
    queryKey: ['alerts', session.mode, session.range, session.gen, session.evidence, filters],
    queryFn: () => loadAlerts(session.mode, session.range, session.evidence, session.tokenRef.current, filters),
    refetchInterval: session.mode !== 'replay' && session.stream !== 'live' ? 2000 : false,
  })
  const items = query.data?.items || []
  const [cursor, setCursor] = useState(0)
  const navigate = useNavigate()
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (target && ['INPUT', 'SELECT', 'TEXTAREA'].includes(target.tagName)) return
      if (event.key === 'j' || event.key === 'ArrowDown') { event.preventDefault(); setCursor((value) => Math.min(items.length - 1, value + 1)) }
      if (event.key === 'k' || event.key === 'ArrowUp') { event.preventDefault(); setCursor((value) => Math.max(0, value - 1)) }
      if (event.key === 'Enter' && items[cursor]?.chainId) navigate(`/chains/${items[cursor].chainId}`)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [items, cursor, navigate])

  const grouped = useMemo(() => groupAlerts(items, filters.group), [items, filters.group])
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <Select label="规则" value={filters.rule} onChange={(value) => setFilter('rule', value)} options={['', 'S01', 'S02', 'S03', 'S04', 'S05', 'S08', 'S13', 'S14', 'S15', 'S16', 'S17', 'S18', 'S19', 'S20', 'S21', 'S22']} />
        <Select label="级别" value={filters.severity} onChange={(value) => setFilter('severity', value)} options={[['', '全部'], ['high', '高'], ['medium', '中'], ['low', '低']]} />
        <Select label="阶段" value={filters.phase} onChange={(value) => setFilter('phase', value)} options={[['', '全部'], ['semantic', 'semantic'], ['host_confirmed', 'host_confirmed']]} />
        <Select label="层" value={filters.layer} onChange={(value) => setFilter('layer', value)} options={[['', '全部'], ['D', '决策层'], ['B', '行为层']]} />
        <Select label="分组" value={filters.group} onChange={(value) => setFilter('group', value)} options={[['', '不分组'], ['chain', '按链'], ['agent', '按 Agent'], ['layer', '按层']]} />
        {session.evidence && <input className="rounded border border-line bg-panel px-2 py-1 text-xs" placeholder="agentId" value={filters.agentId} onChange={(event) => setFilter('agentId', event.target.value)} />}
      </div>
      <p className="text-[11px] text-faint">j / k 或方向键切换，Enter 打开调用链。{query.data?.note}</p>
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {query.data && query.data.total === 0 && (
        <EmptyState title="当前筛选下没有告警。这不等于没有风险。">
          <p>采集 online {query.data.coverageSummary?.online ?? 0} · degraded {query.data.coverageSummary?.degraded ?? 0} · offline {query.data.coverageSummary?.offline ?? 0}</p>
          {(query.data.inactiveRules || []).map((rule) => <p key={rule.id}>{rule.id} · {rule.reason}</p>)}
        </EmptyState>
      )}
      <div className="space-y-2">
        {grouped.map((group) => (
          <details key={group.key} open className="rounded-lg border border-line bg-panel">
            <summary className="cursor-pointer px-4 py-2 text-sm text-muted">{group.label} · {group.items.length}</summary>
            <ul>
              {group.items.map((item) => {
                const index = items.indexOf(item)
                const active = index === cursor
                return (
                  <li key={item.id} className={`grid gap-2 border-t border-line px-4 py-2 text-sm md:grid-cols-[7rem_4rem_9rem_6rem_minmax(0,1fr)_auto] ${active ? 'bg-panel-2' : ''}`}>
                    <span className="font-mono text-info">{item.rule}</span>
                    <SeverityBadge value={item.severity} />
                    <PhaseBadge value={item.phase} />
                    <LayerBadge value={item.layer} />
                    <span className="truncate text-muted">{item.title || item.ruleName} {item.agentId || item.agentAlias ? `· ${item.agentId || item.agentAlias}` : ''}</span>
                    <span className="flex items-center justify-end gap-3">
                      <span className="font-mono text-[11px] text-faint">{formatTime(item.createdAt)}</span>
                      {item.chainId ? <Link className="text-info" to={`/chains/${item.chainId}`}>链路</Link> : <span className="text-[11px] text-faint">无链</span>}
                    </span>
                  </li>
                )
              })}
            </ul>
          </details>
        ))}
      </div>
      {query.data && query.data.total > items.length && <p className="text-xs text-faint">还有 {query.data.total - items.length} 条不在这一页。缩小时间或规则后再看。</p>}
    </div>
  )
}

function groupAlerts(items: AlertItem[], group: string) {
  if (!group) return [{ key: 'all', label: `全部 ${items.length}`, items }]
  const map = new Map<string, AlertItem[]>()
  for (const item of items) {
    const key = group === 'chain' ? item.chainId || '无链' : group === 'agent' ? item.agentId || item.agentAlias || '未知 Agent' : group === 'layer' ? layerLabel(item.layer) : '全部'
    map.set(key, [...(map.get(key) || []), item])
  }
  return [...map.entries()].map(([key, groupItems]) => ({ key, label: key, items: groupItems }))
}

async function loadAlerts(mode: string, range: string, evidence: boolean, token: string | null, filters: AlertFilters): Promise<AlertPage> {
  if (mode === 'replay') {
    let items = replay.alerts.filter((item) => {
      if (filters.rule && item.rule !== filters.rule) return false
      if (filters.severity && item.severity !== filters.severity) return false
      if (filters.phase && item.phase !== filters.phase) return false
      if (filters.layer && item.layer !== filters.layer) return false
      if (filters.agentId && item.agentId !== filters.agentId) return false
      if (filters.chainId && item.chainId !== filters.chainId) return false
      if (filters.since && (item.createdAt || 0) < Number(filters.since)) return false
      if (filters.until && (item.createdAt || 0) > Number(filters.until)) return false
      return true
    })
    return { items, total: items.length, publicSummary: true, note: '回放列表', coverageSummary: { online: 3, degraded: 0, offline: 0 }, inactiveRules: replay.overview.inactiveRules }
  }
  const search = new URLSearchParams({ limit: '100', range })
  for (const key of ['rule', 'severity', 'since', 'until'] as const) if (filters[key]) search.set(key, filters[key])
  if (evidence) {
    for (const key of ['phase', 'layer', 'agentId', 'chainId', 'group'] as const) if (filters[key]) search.set(key, filters[key])
  }
  const page = await getJson<AlertPage>(`/runtime/api/v2/alerts?${search}`, token)
  if (!evidence) {
    page.items = page.items.filter((item) => {
      if (filters.phase && item.phase !== filters.phase) return false
      if (filters.layer && item.layer !== filters.layer) return false
      return true
    })
  }
  return page
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: Array<string | [string, string]> }) {
  return (
    <label className="flex items-center gap-1 text-[11px] text-faint">
      {label}
      <select className="rounded border border-line bg-panel px-2 py-1 text-xs text-ink-text" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => {
          const [id, text] = Array.isArray(option) ? option : [option, option || '全部']
          return <option key={id || 'all'} value={id}>{text}</option>
        })}
      </select>
    </label>
  )
}

export function ChainsPage() {
  const session = useSession()
  const query = useQuery({
    queryKey: ['chains', session.mode, session.range, session.gen, session.evidence],
    queryFn: () => {
      if (session.mode === 'replay') {
        return Promise.resolve({ items: replay.chains.map((chain) => ({ chainId: chain.chainId, agentId: chain.agentId, phase: chain.phase, rules: [...new Set(chain.alerts.map((alert) => alert.rule))], alertCount: chain.alerts.length, dataset: 'replay' })) as ChainSummary[], note: replay.note })
      }
      return getJson<{ items: ChainSummary[]; note?: string }>(`/runtime/api/v2/chains?range=${session.range}`, session.tokenRef.current)
    },
    refetchInterval: session.mode !== 'replay' && session.stream !== 'live' ? 2000 : false,
  })
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{query.data?.note || '一条链用同一个 agentId 和 chainId 串起输入、决策和主机行为。'}</p>
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {query.data && !query.data.items.length && <EmptyState title="这个窗口没有调用链。">没有链，不表示主机上没有其他告警。</EmptyState>}
      <div className="space-y-2">
        {(query.data?.items || []).map((chain) => <ChainLink key={chain.chainId || chain.chainAlias} chain={chain} />)}
      </div>
    </div>
  )
}

export function ChainPage() {
  const { chainId = '' } = useParams()
  const session = useSession()
  const [stage, setStage] = useState<'semantic' | 'confirmed'>('confirmed')
  const [selected, setSelected] = useState<SwimEvent | null>(null)
  const query = useQuery({
    queryKey: ['chain', chainId, session.mode, session.gen],
    queryFn: async () => {
      if (session.mode === 'replay') {
        const found = replay.chains.find((chain) => chain.chainId === chainId)
        if (!found) throw new ApiError(404, '回放里没有这条链')
        return found
      }
      return getJson<ChainDetail>(`/runtime/api/v2/chains/${encodeURIComponent(chainId)}`, session.tokenRef.current)
    },
  })
  const chain = query.data
  return (
    <div className="space-y-4">
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {query.error instanceof ApiError && query.error.status === 403 && (
        <button type="button" className="text-sm text-info" onClick={() => session.setMode('replay')}>切换到回放，查看脱敏样例 ch-7f3a</button>
      )}
      {chain && (
        <>
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="font-mono text-lg">{chain.chainId}</h1>
              <p className="text-sm text-muted">{chain.agentId || chain.agentAlias} · {chain.role || '未标注'} · {chain.dataset === 'replay' ? '回放' : '线上'}</p>
            </div>
            <div className="flex rounded-md border border-line p-0.5">
              <button type="button" className={`rounded px-3 py-1 text-xs ${stage === 'semantic' ? 'bg-panel-2' : 'text-muted'}`} onClick={() => setStage('semantic')}>语义段告警那一刻</button>
              <button type="button" className={`rounded px-3 py-1 text-xs ${stage === 'confirmed' ? 'bg-panel-2' : 'text-muted'}`} onClick={() => setStage('confirmed')}>主机确认之后</button>
            </div>
          </div>
          <div className="flex flex-wrap gap-3 text-[11px] text-muted">
            <span className="flex items-center gap-1"><i className="inline-block h-2 w-2 bg-signal" />高风险调用与告警</span>
            <span className="flex items-center gap-1"><i className="inline-block h-2 w-2 bg-amber" />不受信片段</span>
            <span className="flex items-center gap-1"><i className="inline-block h-2 w-2 bg-info" />关联边</span>
          </div>
          <Panel>
            <Swimlane events={chain.events} edges={chain.edges} spanSeconds={chain.spanSeconds} semanticAt={chain.semanticAt} confirmedAt={chain.confirmedAt} stage={stage} onSelect={setSelected} />
          </Panel>
          <div className="grid gap-3 lg:grid-cols-2">
            <Panel title="链路信息">
              <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-y-2 text-sm">
                <dt className="text-faint">chainId</dt><dd className="font-mono text-xs">{chain.chainId}</dd>
                <dt className="text-faint">Agent</dt><dd>{chain.agentId || chain.agentAlias} · {chain.role || '未标注'}</dd>
                <dt className="text-faint">S03 阶段</dt><dd><PhaseBadge value={stage === 'confirmed' ? chain.phase : 'semantic'} /></dd>
                <dt className="text-faint">可信度</dt><dd><ConfidenceBadge value={chain.confidence} /></dd>
                <dt className="text-faint">延迟</dt><dd>{delayPhrase('语义段', '语义时间超前', chain.latency?.semanticSeconds)} · {delayPhrase('主机确认', '主机时间超前', chain.latency?.hostSeconds)}</dd>
                <dt className="text-faint">关联依据</dt><dd className="text-muted">{chain.basis || '—'}</dd>
              </dl>
            </Panel>
            <Panel title="文件改动证据">
              {chain.files.length ? (
                <table className="w-full text-left text-sm">
                  <thead className="text-[11px] text-faint"><tr><th className="py-1 font-medium">路径</th><th className="font-medium">改动前</th><th className="font-medium">改动后</th><th className="font-medium">规则</th></tr></thead>
                  <tbody>
                    {chain.files.map((file) => (
                      <tr key={file.path} className="border-t border-line">
                        <td className="py-2 font-mono text-xs">{file.path}</td>
                        <td className="font-mono text-xs">{file.before || '—'}</td>
                        <td className="font-mono text-xs">{file.after || '—'}</td>
                        <td className="font-mono text-xs">{file.rule}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <EmptyState title="这条链没有带哈希的文件改动。" />}
            </Panel>
          </div>
          <p className="text-xs text-faint">点任一事件块查看原始字段。inferred 只展示，不单独当成告警。</p>
          <Dialog.Root open={!!selected} onOpenChange={(open) => { if (!open) setSelected(null) }}>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 bg-black/50" />
              <Dialog.Content className="fixed top-0 right-0 flex h-full w-[min(440px,100%)] flex-col border-l border-line bg-panel p-5">
                <Dialog.Title className="text-base font-semibold">{selected?.title}</Dialog.Title>
                <Dialog.Description className="mt-1 font-mono text-xs text-muted">{selected?.sub}</Dialog.Description>
                <dl className="mt-4 space-y-2 overflow-auto text-sm">
                  {Object.entries(selected?.drawer || {}).map(([key, value]) => (
                    <div key={key}>
                      <dt className="text-[11px] text-faint">{key}</dt>
                      <dd className="font-mono text-xs break-all">{renderValue(value)}</dd>
                    </div>
                  ))}
                  {!selected?.drawer && <p className="text-muted">这条示意块没有更多字段。</p>}
                </dl>
                <button type="button" className="mt-4 self-end text-sm text-muted" onClick={() => setSelected(null)}>关闭</button>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
        </>
      )}
    </div>
  )
}

export function DrillPage() {
  const session = useSession()
  const query = useQuery({
    queryKey: ['drill', session.mode, session.gen, session.evidence],
    queryFn: () => session.mode === 'replay' ? Promise.resolve(replay.drill) : getJson<DrillReport>('/runtime/api/v2/drill', session.tokenRef.current),
    refetchInterval: session.mode !== 'replay' && session.stream !== 'live' ? 2000 : false,
  })
  const data = query.data
  return (
    <div className="space-y-4">
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {data && (
        <>
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-lg font-semibold">{data.label || '演练计分板'}</h1>
              <p className="text-sm text-muted">{data.note}</p>
            </div>
          </div>
          {data.hidden ? <EmptyState title="计分板没有对匿名开放。">操作员或裁判凭证可以看命中和命令。公开时也只给汇总，不给命令。</EmptyState> : (
            <>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <RateCard rate={data.rates.p0} />
                <RateCard rate={data.rates.s02} />
                <RateCard rate={data.rates.s03} />
                <RateCard rate={data.rates.fresh} />
              </div>
              <Panel title="剧本">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-[11px] text-faint"><tr><th className="py-2 font-medium">剧本</th><th className="font-medium">红方动作</th><th className="font-medium">期望规则</th><th className="font-medium">实际命中</th><th className="font-medium">延迟</th><th className="font-medium">计入</th></tr></thead>
                    <tbody>
                      {data.rows.map((row) => (
                        <tr key={row.id} className="border-t border-line align-top">
                          <td className="py-2 font-mono text-xs">{row.id}</td>
                          <td className="py-2">
                            {row.action}
                            {!!row.matches?.length && (
                              <details className="mt-1 text-xs text-muted">
                                <summary className="cursor-pointer">匹配到的告警</summary>
                                <ul className="mt-1 space-y-1">
                                  {row.matches.map((match) => (
                                    <li key={match.alertId + match.rule}>
                                      <span className="font-mono">{match.rule}</span> {match.alertId}
                                      {match.chainId && <> · <Link className="text-info" to={`/chains/${match.chainId}`}>{match.chainId}</Link></>}
                                      {match.command && <div className="font-mono text-[11px]">{match.command}</div>}
                                    </li>
                                  ))}
                                </ul>
                              </details>
                            )}
                          </td>
                          <td className="py-2 text-muted">{row.expected}</td>
                          <td className="py-2"><Badge tone={row.tone === 'success' ? 'ok' : row.tone === 'warning' ? 'warn' : row.tone === 'danger' ? 'danger' : 'neutral'}>{row.result}</Badge></td>
                          <td className="py-2 font-mono text-xs">{row.latency}</td>
                          <td className="py-2 text-muted">{row.cohort}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!data.rows.length && <EmptyState title="drill.yaml 里还没有剧本。" />}
                </div>
              </Panel>
            </>
          )}
        </>
      )}
    </div>
  )
}

function RateCard({ rate }: { rate: DrillReport['rates']['p0'] }) {
  const shown = rate.rate == null ? rate.detail : `${Math.round(rate.rate * 100)}%`
  return (
    <div className={`rounded-lg border px-4 py-3 ${rate.belowTarget ? 'border-signal/60 bg-signal/10' : 'border-line bg-panel'}`}>
      <div className="text-[11px] tracking-wider text-faint uppercase">{rate.label}</div>
      <div className={`mt-1 font-mono text-2xl tabular-nums ${rate.belowTarget ? 'text-signal' : ''}`}>{shown}</div>
      <div className="mt-1 text-xs text-muted">{rate.detail}{rate.belowTarget ? ' · 低于 90%' : ''}</div>
    </div>
  )
}

export function CoveragePage() {
  const session = useSession()
  const query = useQuery({
    queryKey: ['coverage', session.mode, session.gen, session.evidence],
    queryFn: () => session.mode === 'replay' ? Promise.resolve(replay.coverage) : getJson<CoverageReport>('/runtime/api/v2/coverage', session.tokenRef.current),
    refetchInterval: session.mode !== 'replay' && session.stream !== 'live' ? 2000 : false,
  })
  const data = query.data
  return (
    <div className="space-y-4">
      <QueryNote error={query.error as Error | null} loading={query.isLoading} />
      {data && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <Metric value={String(data.sources.online)} label="在线" detail={`共 ${data.sources.total} 个采集源`} />
            <Metric value={String(data.sources.degraded)} label="降级" detail={data.recentLoss ? '近期窗口有丢失或背压' : '近期窗口没有新增丢失'} />
            <Metric value={String(data.gapCount ?? 0)} label="断连区间" detail="心跳超过 35 秒记一次" />
          </div>
          <Panel title="没生效的规则">
            <p className="mb-3 text-sm text-muted">{data.note} 内核阻断保持关闭。</p>
            <ul className="space-y-1 text-sm">{(data.inactiveRules || []).map((rule) => <li key={rule.id}><span className="font-mono text-info">{rule.id}</span> {rule.reason}</li>)}</ul>
            {!data.inactiveRules?.length && <EmptyState title="当前能确认的规则都已启用。" />}
          </Panel>
          {data.sourceDetails && (
            <Panel title="采集源">
              <div className="space-y-3">
                {data.sourceDetails.map((source) => (
                  <div key={source.source} className="rounded border border-line px-3 py-2 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs">{source.source}</span>
                      <StateBadge value={source.state} />
                      {source.host && <span className="text-muted">{source.host}</span>}
                      <span className="text-xs text-faint">{source.ageSeconds != null ? `${source.ageSeconds} s` : ''}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted">{source.lossWarning || '没有近期损失提示'}</p>
                    <p className="mt-1 font-mono text-[11px] text-faint">{Object.entries(source.layers || {}).map(([key, value]) => `${key}=${value}`).join(' · ') || '无层状态'}</p>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  )
}
