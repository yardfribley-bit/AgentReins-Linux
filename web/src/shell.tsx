import { NavLink, Outlet } from 'react-router-dom'
import { TopBar } from './ui'

const nav = [
  { to: '/', label: '总览', ready: true },
  { to: '/chains', label: '调用链', ready: true },
  { to: '/alerts', label: '告警中心', ready: true },
  { to: '/drill', label: '演练模式', ready: true },
  { to: '/agents', label: 'Agent 画像', ready: false },
  { to: '/coverage', label: '采集与覆盖', ready: true },
  { to: '/export', label: '取证导出', ready: false },
  { to: '/rules', label: '规则库', ready: false },
]

export function Shell() {
  return (
    <div className="min-h-screen">
      <TopBar />
      <div className="grid md:grid-cols-[168px_minmax(0,1fr)]">
        <nav className="flex gap-1 overflow-x-auto border-b border-line px-2 py-2 md:block md:min-h-[calc(100vh-58px)] md:border-r md:border-b-0 md:px-3 md:py-4">
          {nav.map((item) => item.ready ? (
            <NavLink key={item.to} to={item.to} end={item.to === '/'} className={({ isActive }) => `block rounded px-2 py-2 text-sm whitespace-nowrap ${isActive ? 'bg-panel-2 font-semibold text-ink-text' : 'text-muted'}`}>{item.label}</NavLink>
          ) : (
            <div key={item.to} className="flex items-center justify-between rounded px-2 py-2 text-sm whitespace-nowrap text-faint/70" title="P1，这一版还没有">
              <span>{item.label}</span>
              <span className="font-mono text-[10px]">P1</span>
            </div>
          ))}
        </nav>
        <main className="min-w-0 px-4 py-4 md:px-6 md:py-5">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
