import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Register from './pages/Register'
import Today from './pages/Today'
import Projects from './pages/Projects'
import Scans from './pages/Scans'
import Vulnerabilities from './pages/Vulnerabilities'
import Tools from './pages/Tools'
import Settings from './pages/Settings'
import AIAnalysis from './pages/AIAnalysis'
import Rules from './pages/Rules'
import Assets from './pages/Assets'
import Reports from './pages/Reports'
import AuditLog from './pages/AuditLog'
import UserManagement from './pages/UserManagement'
import Alerts from './pages/Alerts'
import Investigation from './pages/Investigation'
import Tickets from './pages/Tickets'
import KnowledgeBase from './pages/KnowledgeBase'
import KnowledgeDetail from './pages/KnowledgeDetail'
import KnowledgeEditor from './pages/KnowledgeEditor'
import Skills from './pages/Skills'
import ErrorBoundary from './components/ErrorBoundary'
import { I18nProvider } from './i18n'

function Protected({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('sentinel_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <I18nProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<Protected><Layout /></Protected>}>
          <Route index element={<Today />} />
          <Route path="investigation" element={<ErrorBoundary><Investigation /></ErrorBoundary>} />
          <Route path="tickets" element={<ErrorBoundary><Tickets /></ErrorBoundary>} />
          <Route path="projects" element={<Projects />} />
          <Route path="scans" element={<Scans />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="tools" element={<Tools />} />
          <Route path="settings" element={<Settings />} />
          <Route path="ai" element={<AIAnalysis />} />
          <Route path="rules" element={<ErrorBoundary><Rules /></ErrorBoundary>} />
          <Route path="assets" element={<ErrorBoundary><Assets /></ErrorBoundary>} />
          <Route path="reports" element={<ErrorBoundary><Reports /></ErrorBoundary>} />
          <Route path="audit" element={<ErrorBoundary><AuditLog /></ErrorBoundary>} />
          <Route path="users" element={<ErrorBoundary><UserManagement /></ErrorBoundary>} />
          <Route path="alerts" element={<ErrorBoundary><Alerts /></ErrorBoundary>} />
          <Route path="knowledge-base" element={<ErrorBoundary><KnowledgeBase /></ErrorBoundary>} />
          <Route path="knowledge-base/new" element={<ErrorBoundary><KnowledgeEditor /></ErrorBoundary>} />
          <Route path="knowledge-base/:id/edit" element={<ErrorBoundary><KnowledgeEditor /></ErrorBoundary>} />
          <Route path="knowledge-base/:id" element={<ErrorBoundary><KnowledgeDetail /></ErrorBoundary>} />
          <Route path="skills" element={<ErrorBoundary><Skills /></ErrorBoundary>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </I18nProvider>
  )
}
