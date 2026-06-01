import React from 'react'
import PropTypes from 'prop-types'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { ProjectPermissionsProvider } from './context/ProjectPermissions.jsx'

class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (this.state.err) {
      return (
        <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', width:'100%', height:'100%', background:'#08090b', color:'#cc2233', fontFamily:'JetBrains Mono', fontSize:13, gap:12, padding:24 }}>
          <div style={{ fontSize:16, fontWeight:700 }}>RootNotes — rendering error</div>
          <div style={{ color:'#c8cdd6', maxWidth:600, textAlign:'center', lineHeight:1.6 }}>{String(this.state.err)}</div>
          <button onClick={() => { localStorage.clear(); globalThis.location.reload(); }}
            style={{ marginTop:8, background:'#cc2233', border:'none', borderRadius:6, padding:'8px 20px', cursor:'pointer', color:'#fff', fontSize:12, fontFamily:'JetBrains Mono' }}>
            Clear cache &amp; reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

ErrorBoundary.propTypes = {
  children: PropTypes.node,
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <ErrorBoundary>
    <ProjectPermissionsProvider>
      <App />
    </ProjectPermissionsProvider>
  </ErrorBoundary>
)
