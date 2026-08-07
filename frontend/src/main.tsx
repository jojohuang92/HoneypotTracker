import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import { TimeRangeProvider } from './context/TimeRangeContext.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <TimeRangeProvider>
        <App />
      </TimeRangeProvider>
    </BrowserRouter>
  </StrictMode>,
)
