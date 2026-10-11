import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import MatrixBackground from './components/background/MatrixBackground';
import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';
import LandingPage from './pages/LandingPage';
import DashboardPage from './pages/DashboardPage';
import HowItWorksPage from './pages/HowItWorksPage';
import AboutPage from './pages/AboutPage';
import FAQPage from './pages/FAQPage';

function PageTransition({ children }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -16 }}
      transition={{ duration: 0.35, ease: 'easeInOut' }}
    >
      {children}
    </motion.div>
  );
}

function AppRoutes() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<PageTransition><LandingPage /></PageTransition>} />
        <Route path="/analyze" element={<PageTransition><DashboardPage /></PageTransition>} />
        <Route path="/how-it-works" element={<PageTransition><HowItWorksPage /></PageTransition>} />
        <Route path="/about" element={<PageTransition><AboutPage /></PageTransition>} />
        <Route path="/faq" element={<PageTransition><FAQPage /></PageTransition>} />
        <Route path="*" element={<PageTransition><NotFound /></PageTransition>} />
      </Routes>
    </AnimatePresence>
  );
}

function NotFound() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '1rem', textAlign: 'center', paddingTop: 64 }}>
      <div style={{ fontFamily: 'Orbitron', fontSize: 80, fontWeight: 900, color: 'rgba(0,240,255,0.15)', lineHeight: 1 }}>404</div>
      <div style={{ fontFamily: 'Rajdhani', fontSize: 24, color: '#e0f4ff' }}>Page Not Found</div>
      <div style={{ fontFamily: 'Space Mono', fontSize: 11, color: '#6b8fa8' }}>This sector of the grid does not exist.</div>
      <a href="/" className="btn-primary" style={{ marginTop: '1rem' }}>← Return to Base</a>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <MatrixBackground />
      <Navbar />
      <main style={{ position: 'relative', zIndex: 1 }}>
        <AppRoutes />
      </main>
      <Footer />
    </BrowserRouter>
  );
}
