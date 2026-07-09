import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// ─── Request interceptor: attach Bearer token ───
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ─── Response interceptor: token expiry handling ───
let _isRedirecting = false

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && !_isRedirecting) {
      // Check if token is actually expired (not just a bad request)
      const token = localStorage.getItem('sentinel_token')
      if (token) {
        // Try to decode payload to check expiry
        try {
          const payload = JSON.parse(atob(token.split('.')[1]))
          const expMs = payload.exp * 1000
          const nowMs = Date.now()
          // If token expired more than 5 minutes ago, redirect to login
          if (expMs < nowMs - 5 * 60 * 1000) {
            _isRedirecting = true
            localStorage.removeItem('sentinel_token')
            localStorage.removeItem('sentinel_user')
            // Small delay so in-flight requests can fail gracefully
            setTimeout(() => {
              _isRedirecting = false
              if (window.location.pathname !== '/login') {
                window.location.href = '/login'
              }
            }, 300)
          } else if (expMs < nowMs) {
            // Token just expired — redirect immediately
            _isRedirecting = true
            localStorage.removeItem('sentinel_token')
            localStorage.removeItem('sentinel_user')
            setTimeout(() => {
              _isRedirecting = false
              if (window.location.pathname !== '/login') {
                window.location.href = '/login'
              }
            }, 100)
          }
          // If token appears valid but 401 returned, don't redirect — likely a permissions issue
        } catch {
          // Couldn't decode token — treat as expired
          _isRedirecting = true
          localStorage.removeItem('sentinel_token')
          localStorage.removeItem('sentinel_user')
          setTimeout(() => {
            _isRedirecting = false
            if (window.location.pathname !== '/login') {
              window.location.href = '/login'
            }
          }, 100)
        }
      } else {
        // No token at all
        if (window.location.pathname !== '/login') {
          _isRedirecting = true
          setTimeout(() => {
            _isRedirecting = false
            window.location.href = '/login'
          }, 100)
        }
      }
    }
    return Promise.reject(err)
  }
)

// ─── Token expiry warning: fire a custom event 5 min before expiry ───
function scheduleTokenExpiryWarning() {
  const token = localStorage.getItem('sentinel_token')
  if (!token) return
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    const expMs = payload.exp * 1000
    const warnAt = expMs - 5 * 60 * 1000  // 5 min before
    const delay = warnAt - Date.now()
    if (delay > 0) {
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('sentinel:token-expiring', { detail: { expiresIn: 5 } }))
      }, delay)
    }
  } catch { /* ignore */ }
}

scheduleTokenExpiryWarning()

export default api
