import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Home from './pages/Home';
import Docs from './pages/Docs';
import Commander from './pages/Commander';
import Proof from './pages/Proof';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/docs" element={<Docs />} />
        <Route path="/proof" element={<Proof />} />
        {/* Backward-compatible route only. The operator surface is named Operations. */}
        <Route path="/console" element={<Navigate to="/docs#operations" replace />} />
        <Route path="/commander" element={<Commander />} />
      </Routes>
    </BrowserRouter>
  );
}
