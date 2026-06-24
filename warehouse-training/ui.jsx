// Shared UI primitives for the warehouse-training app.

// ---- Icon: builds a real Lucide SVG imperatively (stable across re-renders) ----
function Icon({ name, size = 20, color, strokeWidth = 2, style }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    const L = window.lucide;
    const host = ref.current;
    if (!L || !host) return;
    const pascal = name.split("-").map((s) => s.charAt(0).toUpperCase() + s.slice(1)).join("");
    const node = (L.icons && (L.icons[pascal] || L.icons[name])) || L[pascal];
    host.innerHTML = "";
    if (node && L.createElement) {
      const el = L.createElement(node);
      el.setAttribute("width", size);
      el.setAttribute("height", size);
      el.setAttribute("stroke", color || "currentColor");
      el.setAttribute("stroke-width", strokeWidth);
      host.appendChild(el);
    }
  });
  return <span ref={ref} style={{ display: "inline-flex", width: size, height: size, color: color, flex: "0 0 auto", ...style }} />;
}

// ---- Receiver badge (Бар / Магазин / Оба) ----
function RecBadge({ rec, withIcon = true }) {
  const icon = rec.key === "bar" ? "coffee" : rec.key === "mag" ? "store" : "circle-dot";
  return (
    <span className={"badge " + rec.key}>
      {withIcon && <Icon name={icon} size={12} strokeWidth={2.4} />}
      {rec.label}
    </span>
  );
}

// ---- Pill button / chip ----
function Chip({ active, onClick, children, icon }) {
  return (
    <button onClick={onClick} style={{
      display: "inline-flex", alignItems: "center", gap: 7, whiteSpace: "nowrap",
      fontFamily: "var(--font-sans)", fontSize: 13, fontWeight: 600, letterSpacing: ".02em",
      padding: "9px 15px", borderRadius: 999, cursor: "pointer",
      border: "1px solid " + (active ? "transparent" : "var(--line-strong)"),
      background: active ? "var(--gold)" : "transparent",
      color: active ? "var(--choc-900)" : "var(--cream-dim)",
      transition: "all .15s ease",
    }}>
      {icon && <Icon name={icon} size={15} strokeWidth={2.2} />}
      {children}
    </button>
  );
}

// ---- Primary / secondary buttons (app-themed) ----
function Btn({ children, onClick, variant = "primary", icon, iconRight, full, disabled, style }) {
  const styles = {
    primary: { background: "var(--gold)", color: "var(--choc-900)" },
    secondary: { background: "var(--choc-600)", color: "var(--cream)" },
    ghost: { background: "transparent", color: "var(--cream-dim)", border: "1px solid var(--line-strong)" },
  };
  return (
    <button onClick={onClick} disabled={disabled} style={{
      display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 9,
      fontFamily: "var(--font-sans)", fontSize: 14, fontWeight: 700, letterSpacing: ".08em",
      textTransform: "uppercase", padding: "15px 22px", borderRadius: 14, border: "none",
      cursor: disabled ? "not-allowed" : "pointer", width: full ? "100%" : "auto",
      opacity: disabled ? 0.4 : 1, transition: "filter .15s ease, transform .1s ease",
      ...styles[variant], ...style,
    }}
      onMouseDown={(e) => !disabled && (e.currentTarget.style.transform = "scale(.98)")}
      onMouseUp={(e) => (e.currentTarget.style.transform = "")}
      onMouseLeave={(e) => (e.currentTarget.style.transform = "")}
    >
      {icon && <Icon name={icon} size={18} />}
      {children}
      {iconRight && <Icon name={iconRight} size={18} />}
    </button>
  );
}

// ---- Top bar ----
function TopBar({ title, onBack, right, subtitle }) {
  return (
    <div style={{
      position: "sticky", top: 0, zIndex: 10, background: "rgba(34,20,9,0.86)",
      backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      borderBottom: "1px solid var(--line)", padding: "14px 18px",
      display: "flex", alignItems: "center", gap: 12, minHeight: 58,
    }}>
      {onBack && (
        <button onClick={onBack} aria-label="Назад" style={{
          background: "var(--choc-700)", border: "1px solid var(--line)", color: "var(--cream)",
          width: 38, height: 38, borderRadius: 11, display: "inline-flex", alignItems: "center",
          justifyContent: "center", cursor: "pointer", flex: "0 0 auto",
        }}><Icon name="chevron-left" size={20} /></button>
      )}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: ".04em", textTransform: "uppercase", color: "var(--cream)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{title}</div>
        {subtitle && <div style={{ fontSize: 12, color: "var(--cream-mute)" }}>{subtitle}</div>}
      </div>
      {right}
    </div>
  );
}

// ---- Bottom navigation ----
function BottomNav({ tab, onTab }) {
  const items = [
    { key: "home", label: "Главная", icon: "house" },
    { key: "guide", label: "Заявка", icon: "list-checks" },
    { key: "catalog", label: "Склад", icon: "boxes" },
    { key: "search", label: "Поиск", icon: "search" },
  ];
  return (
    <nav style={{
      position: "absolute", bottom: 0, left: 0, right: 0, zIndex: 30,
      background: "rgba(28,16,8,0.92)", backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)",
      borderTop: "1px solid var(--line)", display: "grid", gridTemplateColumns: "repeat(4,1fr)",
      padding: "8px 6px calc(8px + env(safe-area-inset-bottom))",
    }}>
      {items.map((it) => {
        const on = tab === it.key;
        return (
          <button key={it.key} onClick={() => onTab(it.key)} style={{
            background: "none", border: "none", cursor: "pointer", display: "flex",
            flexDirection: "column", alignItems: "center", gap: 4, padding: "6px 0",
            color: on ? "var(--gold)" : "var(--cream-mute)",
          }}>
            <Icon name={it.icon} size={22} strokeWidth={on ? 2.4 : 2} />
            <span style={{ fontSize: 10.5, fontWeight: on ? 700 : 500, letterSpacing: ".04em" }}>{it.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

// ---- viewport hook ----
function useIsDesktop(bp) {
  bp = bp || 900;
  const [d, setD] = React.useState(() => typeof window !== "undefined" && window.innerWidth >= bp);
  React.useEffect(() => {
    const on = () => setD(window.innerWidth >= bp);
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, [bp]);
  return d;
}

// ---- Desktop sidebar nav ----
function Sidebar({ tab, onTab }) {
  const items = [
    { key: "home", label: "Главная", icon: "house" },
    { key: "guide", label: "Как создать заявку", icon: "list-checks" },
    { key: "catalog", label: "Что есть на складе", icon: "boxes" },
    { key: "search", label: "Поиск", icon: "search" },
  ];
  return (
    <aside style={{
      width: 264, flex: "0 0 auto", background: "var(--choc-900)", borderRight: "1px solid var(--line)",
      display: "flex", flexDirection: "column", padding: "26px 18px",
    }}>
      <img src="./assets/logos/yahya-logo-gold.png" alt="YAHYA" style={{ height: 30, alignSelf: "flex-start", marginLeft: 8, marginBottom: 6 }} />
      <div style={{ fontSize: 11, letterSpacing: ".16em", textTransform: "uppercase", color: "var(--cream-mute)", marginLeft: 8, marginBottom: 26 }}>Склад ХОЗ</div>
      <nav style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {items.map((it) => {
          const on = tab === it.key;
          return (
            <button key={it.key} onClick={() => onTab(it.key)} style={{
              display: "flex", alignItems: "center", gap: 13, textAlign: "left", cursor: "pointer",
              padding: "12px 14px", borderRadius: 13, border: "none",
              background: on ? "var(--gold)" : "transparent",
              color: on ? "var(--choc-900)" : "var(--cream-dim)",
              fontFamily: "var(--font-sans)", fontSize: 14, fontWeight: on ? 700 : 600, letterSpacing: ".01em",
              transition: "background .15s ease, color .15s ease",
            }}
              onMouseEnter={(e) => { if (!on) e.currentTarget.style.background = "var(--choc-700)"; }}
              onMouseLeave={(e) => { if (!on) e.currentTarget.style.background = "transparent"; }}
            >
              <Icon name={it.icon} size={20} strokeWidth={on ? 2.4 : 2} />
              {it.label}
            </button>
          );
        })}
      </nav>
      <div style={{ marginTop: "auto", fontSize: 11.5, color: "var(--cream-mute)", lineHeight: 1.5, marginLeft: 8 }}>
        Склад Ибраимова · Бишкек<br />Внутренний справочник YAHYA
      </div>
    </aside>
  );
}

Object.assign(window, { Icon, RecBadge, Chip, Btn, TopBar, BottomNav, Sidebar, useIsDesktop });
