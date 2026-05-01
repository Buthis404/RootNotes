import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { ProjectPermissionsProvider } from './context/ProjectPermissions.jsx'

ReactDOM.createRoot(document.getElementById('root')).render(
  <ProjectPermissionsProvider>
    <App />
  </ProjectPermissionsProvider>
)
