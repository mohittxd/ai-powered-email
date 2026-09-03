import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 60000,
})

// ── JWT token interceptor ─────────────────────────────────────────────────────
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('ef_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// ── Email Analysis ──────────────────────────────────────────────────────────
export const analyzeEmail = async (file = null, rawHeaders = null, caseId = null) => {
  const form = new FormData()
  if (file) form.append('file', file)
  if (rawHeaders) form.append('raw_headers', rawHeaders)
  if (caseId) form.append('case_id', caseId)
  form.append('analyst_id', 'demo-analyst-001')
  const res = await api.post('/analyze-email', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}

// ── Auth ─────────────────────────────────────────────────────────────────────
export const login = async (email, password) =>
  (await api.post('/auth/login', { email, password })).data
export const getMe = async () => (await api.get('/auth/me')).data

// ── Cases ───────────────────────────────────────────────────────────────────
export const listCases = async (params = {}) => (await api.get('/cases', { params })).data
export const createCase = async (title) =>
  (await api.post('/cases', { title, analyst_id: 'demo-analyst-001' })).data
export const getCase = async (id) => (await api.get(`/cases/${id}`)).data
export const updateCaseStatus = async (id, status) =>
  (await api.patch(`/cases/${id}/status`, null, { params: { status } })).data
export const deleteCase = async (id) => (await api.delete(`/cases/${id}`)).data
export const linkEmailToCase = async (caseId, emailId) =>
  (await api.post(`/cases/${caseId}/emails/${emailId}`)).data

// ── IOC Database ─────────────────────────────────────────────────────────────
export const listIocs = async (params = {}) => (await api.get('/iocs', { params })).data
export const searchIocs = async (q) => (await api.get('/iocs/search', { params: { q } })).data
export const iocStats = async () => (await api.get('/iocs/stats')).data

// ── Audit Log ────────────────────────────────────────────────────────────────
export const listAudit = async (params = {}) => (await api.get('/audit', { params })).data
export const auditStats = async () => (await api.get('/audit/stats')).data

// ── Platform Stats ───────────────────────────────────────────────────────────
export const statsOverview = async () => (await api.get('/stats/overview')).data

// ── Campaigns ────────────────────────────────────────────────────────────────
export const listCampaigns = async () => (await api.get('/campaigns')).data

// ── Reports ───────────────────────────────────────────────────────────────────
export const getJsonReport = (emailId) => `/api/v1/emails/${emailId}/report.json`
export const getPdfReport = (emailId) => `/api/v1/emails/${emailId}/report.pdf`
export const getCaseJsonReport = (caseId) => `/api/v1/cases/${caseId}/report`
export const getCasePdfReport = (caseId) => `/api/v1/cases/${caseId}/report/pdf`

export default api

