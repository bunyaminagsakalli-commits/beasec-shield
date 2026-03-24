import { Link, useLocation } from "react-router-dom";
import { Shield, Home, Search, LayoutDashboard, Bell, FileText, Info, Menu, X } from "lucide-react";
import { useState } from "react";

const navItems = [
  { to: "/", label: "Home", icon: Home },
  { to: "/scan", label: "Scanner", icon: Search },
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/report", label: "Report", icon: FileText },
  { to: "/about", label: "About", icon: Info },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Nav */}
      <header className="sticky top-0 z-50 glass-card border-b border-border/50 backdrop-blur-2xl">
        <div className="container flex items-center justify-between h-16 px-4">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-primary/15">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <span className="font-bold text-lg tracking-tight">BEASEC</span>
          </Link>

          {/* Desktop nav */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map(item => (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  location.pathname === item.to
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                }`}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            ))}
          </nav>

          {/* Mobile toggle */}
          <button onClick={() => setMobileOpen(!mobileOpen)} className="md:hidden p-2 rounded-lg hover:bg-secondary">
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        {/* Mobile nav */}
        {mobileOpen && (
          <nav className="md:hidden border-t border-border/50 p-3 space-y-1">
            {navItems.map(item => (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                  location.pathname === item.to
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                }`}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            ))}
          </nav>
        )}
      </header>

      {/* Main content */}
      <main className="flex-1">{children}</main>

      {/* Footer */}
      <footer className="border-t border-border/50 py-6">
        <div className="container px-4 text-center text-sm text-muted-foreground space-y-1">
          <p>© 2026 BEASEC. All rights reserved.</p>
          <p className="text-xs">Developed by Ekrem Ağsakallı — Riga Nordic University</p>
          <p className="text-xs opacity-60">Academic Prototype — Cybersecurity Monitoring System</p>
        </div>
      </footer>

      {/* Mobile bottom nav */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-50 glass-card border-t border-border/50 backdrop-blur-2xl">
        <div className="flex items-center justify-around py-2">
          {navItems.slice(0, 5).map(item => (
            <Link
              key={item.to}
              to={item.to}
              className={`flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
                location.pathname === item.to
                  ? "text-primary"
                  : "text-muted-foreground"
              }`}
            >
              <item.icon className="h-5 w-5" />
              <span>{item.label}</span>
            </Link>
          ))}
        </div>
      </nav>
    </div>
  );
}
