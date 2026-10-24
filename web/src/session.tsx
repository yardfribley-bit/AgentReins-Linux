import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useMemo, useRef, useState, type MutableRefObject, type ReactNode } from 'react'
import { getMe } from './api'
import type { Me, Mode, RangeKey, StreamState } from './types'

interface SessionValue {
  mode: Mode
  setMode: (mode: Mode) => void
  range: RangeKey
  setRange: (range: RangeKey) => void
  token: string | null
  tokenRef: MutableRefObject<string | null>
  setToken: (token: string | null) => void
  gen: number
  me?: Me
  role: string
  evidence: boolean
  stream: StreamState
}

const SessionContext = createContext<SessionValue | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>('live')
  const [range, setRange] = useState<RangeKey>('1h')
  const [token, setTokenState] = useState<string | null>(null)
  const [gen, setGen] = useState(0)
  const [stream, setStream] = useState<StreamState>('connecting')
  const tokenRef = useRef<string | null>(null)
  const client = useQueryClient()

  const setToken = (next: string | null) => {
    tokenRef.current = next
    setTokenState(next)
    setGen((value) => value + 1)
  }

  const setMode = (next: Mode) => {
    setModeState(next)
    if (next === 'drill') setRange('drill')
    if (next === 'live') setRange('1h')
  }

  const meQuery = useQuery({
    queryKey: ['me', gen],
    queryFn: () => getMe(tokenRef.current),
    enabled: mode !== 'replay',
    retry: false,
  })

  const role = mode === 'replay' ? 'viewer' : meQuery.data?.role || 'viewer'
  const evidence = role === 'operator' || role === 'referee'

  useEffect(() => {
    if (mode === 'replay') {
      setStream('replay')
      return
    }
    let stop = false
    let timer = 0
    let abort: AbortController | undefined
    let lastInvalidate = 0
    const connect = async () => {
      abort = new AbortController()
      setStream('connecting')
      try {
        const headers: Record<string, string> = { Accept: 'text/event-stream' }
        if (tokenRef.current) headers.Authorization = 'Bearer ' + tokenRef.current
        const response = await fetch('/runtime/api/v2/stream', { headers, signal: abort.signal })
        if (!response.ok || !response.body) throw new Error('sse')
        setStream('live')
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''
        while (!stop) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const parts = buffer.split('\n\n')
          buffer = parts.pop() || ''
          if (!parts.length) continue
          const now = Date.now()
          if (now - lastInvalidate > 800) {
            lastInvalidate = now
            void client.invalidateQueries({ queryKey: ['overview'] })
            void client.invalidateQueries({ queryKey: ['alerts'] })
            void client.invalidateQueries({ queryKey: ['chains'] })
            void client.invalidateQueries({ queryKey: ['drill'] })
            void client.invalidateQueries({ queryKey: ['coverage'] })
            void client.invalidateQueries({ queryKey: ['agents'] })
          }
        }
        throw new Error('eof')
      } catch {
        if (stop) return
        setStream('polling')
        timer = window.setTimeout(() => void connect(), 2000)
      }
    }
    void connect()
    return () => {
      stop = true
      abort?.abort()
      window.clearTimeout(timer)
    }
  }, [mode, gen, client])

  const value = useMemo<SessionValue>(
    () => ({ mode, setMode, range, setRange, token, tokenRef, setToken, gen, me: meQuery.data, role, evidence, stream }),
    [mode, range, token, gen, meQuery.data, role, evidence, stream],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession() {
  const value = useContext(SessionContext)
  if (!value) throw new Error('session missing')
  return value
}
