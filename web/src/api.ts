import type { Me } from './types'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function getJson<T>(path: string, token: string | null): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = 'Bearer ' + token
  const response = await fetch(path, { headers })
  const body = (await response.json().catch(() => ({}))) as { error?: string }
  if (!response.ok) throw new ApiError(response.status, body.error || '请求失败')
  return body as T
}

export function getMe(token: string | null) {
  return getJson<Me>('/runtime/api/me', token)
}
