import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AlertsPage, ChainPage, ChainsPage, CoveragePage, DrillPage, OverviewPage } from './pages'
import { SessionProvider } from './session'
import { Shell } from './shell'

const client = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
})

const basename = import.meta.env.BASE_URL.replace(/\/$/, '')

export function App() {
  return (
    <QueryClientProvider client={client}>
      <SessionProvider>
        <BrowserRouter basename={basename}>
          <Routes>
            <Route element={<Shell />}>
              <Route index element={<OverviewPage />} />
              <Route path="chains" element={<ChainsPage />} />
              <Route path="chains/:chainId" element={<ChainPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="drill" element={<DrillPage />} />
              <Route path="coverage" element={<CoveragePage />} />
              <Route path="*" element={<p className="text-sm text-muted">这个地址没有对应的 P0 页面。</p>} />
            </Route>
          </Routes>
        </BrowserRouter>
      </SessionProvider>
    </QueryClientProvider>
  )
}
