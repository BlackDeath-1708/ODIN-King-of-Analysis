// Persistent navigation only — no data fetching, no application state.
const NAV_ITEMS = [
  { id: 'overview', label: 'Overview' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'correlation', label: 'Correlation' },
  { id: 'threat-analysis', label: 'Threat Analysis' },
  { id: 'model-performance', label: 'Model Performance' },
  { id: 'export', label: 'Export & Reports' },
  { id: 'architecture', label: 'Architecture' },
]

function Sidebar({ activePage, onNavigate }) {
  return (
    <nav className="sidebar" aria-label="Primary">
      <ul className="sidebar__list">
        {NAV_ITEMS.map((item) => (
          <li key={item.id}>
            <button
              type="button"
              className={`sidebar__link ${activePage === item.id ? 'is-active' : ''}`}
              aria-current={activePage === item.id ? 'page' : undefined}
              onClick={() => onNavigate(item.id)}
            >
              {item.label}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  )
}

export default Sidebar
