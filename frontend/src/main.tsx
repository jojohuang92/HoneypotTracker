import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import { TimeRangeProvider } from './context/TimeRangeContext.tsx'
import { SensorProvider } from './context/SensorContext.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <TimeRangeProvider>
        <SensorProvider>
          <App />
        </SensorProvider>
      </TimeRangeProvider>
    </BrowserRouter>
  </StrictMode>,
)
