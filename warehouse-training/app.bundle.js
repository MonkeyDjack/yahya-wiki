// СОБРАНО build.sh из *.jsx (2026-10-05). Не править руками — правьте .jsx и пересоберите.
// ---- ui.jsx ----
function Icon({ name, size = 20, color, strokeWidth = 2, style }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    const L = window.lucide;
    const host = ref.current;
    if (!L || !host) return;
    const pascal = name.split("-").map((s) => s.charAt(0).toUpperCase() + s.slice(1)).join("");
    const node = L.icons && (L.icons[pascal] || L.icons[name]) || L[pascal];
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
  return /* @__PURE__ */ React.createElement("span", { ref, style: { display: "inline-flex", width: size, height: size, color, flex: "0 0 auto", ...style } });
}
function RecBadge({ rec, withIcon = true }) {
  const icon = rec.key === "bar" ? "coffee" : rec.key === "mag" ? "store" : "circle-dot";
  return /* @__PURE__ */ React.createElement("span", { className: "badge " + rec.key }, withIcon && /* @__PURE__ */ React.createElement(Icon, { name: icon, size: 12, strokeWidth: 2.4 }), rec.label);
}
function RegBadge({ reg, small }) {
  if (!reg) return null;
  const tov = reg.key === "tov";
  return /* @__PURE__ */ React.createElement("span", { style: {
    display: "inline-flex",
    alignItems: "center",
    gap: small ? 4 : 5,
    whiteSpace: "nowrap",
    fontSize: small ? 10 : 11,
    fontWeight: 700,
    letterSpacing: ".05em",
    textTransform: "uppercase",
    padding: small ? "3px 7px" : "4px 9px",
    borderRadius: 999,
    lineHeight: 1,
    border: "1px solid " + (tov ? "rgba(224,138,106,0.55)" : "var(--line-strong)"),
    background: tov ? "rgba(224,138,106,0.16)" : "rgba(231,214,190,0.08)",
    color: tov ? "#e8a98f" : "var(--cream-dim)"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: tov ? "package" : "list-tree", size: small ? 10 : 12, strokeWidth: 2.2 }), reg.label);
}
function Chip({ active, onClick, children, icon }) {
  return /* @__PURE__ */ React.createElement("button", { onClick, style: {
    display: "inline-flex",
    alignItems: "center",
    gap: 7,
    whiteSpace: "nowrap",
    fontFamily: "var(--font-sans)",
    fontSize: 13,
    fontWeight: 600,
    letterSpacing: ".02em",
    padding: "9px 15px",
    borderRadius: 999,
    cursor: "pointer",
    border: "1px solid " + (active ? "transparent" : "var(--line-strong)"),
    background: active ? "var(--gold)" : "transparent",
    color: active ? "var(--choc-900)" : "var(--cream-dim)",
    transition: "all .15s ease"
  } }, icon && /* @__PURE__ */ React.createElement(Icon, { name: icon, size: 15, strokeWidth: 2.2 }), children);
}
function Btn({ children, onClick, variant = "primary", icon, iconRight, full, disabled, style }) {
  const styles = {
    primary: { background: "var(--gold)", color: "var(--choc-900)" },
    secondary: { background: "var(--choc-600)", color: "var(--cream)" },
    ghost: { background: "transparent", color: "var(--cream-dim)", border: "1px solid var(--line-strong)" }
  };
  return /* @__PURE__ */ React.createElement(
    "button",
    {
      onClick,
      disabled,
      style: {
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 9,
        fontFamily: "var(--font-sans)",
        fontSize: 14,
        fontWeight: 700,
        letterSpacing: ".08em",
        textTransform: "uppercase",
        padding: "15px 22px",
        borderRadius: 14,
        border: "none",
        cursor: disabled ? "not-allowed" : "pointer",
        width: full ? "100%" : "auto",
        opacity: disabled ? 0.4 : 1,
        transition: "filter .15s ease, transform .1s ease",
        ...styles[variant],
        ...style
      },
      onMouseDown: (e) => !disabled && (e.currentTarget.style.transform = "scale(.98)"),
      onMouseUp: (e) => e.currentTarget.style.transform = "",
      onMouseLeave: (e) => e.currentTarget.style.transform = ""
    },
    icon && /* @__PURE__ */ React.createElement(Icon, { name: icon, size: 18 }),
    children,
    iconRight && /* @__PURE__ */ React.createElement(Icon, { name: iconRight, size: 18 })
  );
}
function TopBar({ title, onBack, right, subtitle }) {
  return /* @__PURE__ */ React.createElement("div", { style: {
    position: "sticky",
    top: 0,
    zIndex: 10,
    background: "rgba(34,20,9,0.86)",
    backdropFilter: "blur(12px)",
    WebkitBackdropFilter: "blur(12px)",
    borderBottom: "1px solid var(--line)",
    padding: "14px 18px",
    display: "flex",
    alignItems: "center",
    gap: 12,
    minHeight: 58
  } }, onBack && /* @__PURE__ */ React.createElement("button", { onClick: onBack, "aria-label": "\u041D\u0430\u0437\u0430\u0434", style: {
    background: "var(--choc-700)",
    border: "1px solid var(--line)",
    color: "var(--cream)",
    width: 38,
    height: 38,
    borderRadius: 11,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
    flex: "0 0 auto"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "chevron-left", size: 20 })), /* @__PURE__ */ React.createElement("div", { style: { flex: 1, minWidth: 0 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 15, fontWeight: 700, letterSpacing: ".04em", textTransform: "uppercase", color: "var(--cream)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" } }, title), subtitle && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--cream-mute)" } }, subtitle)), right);
}
function BottomNav({ tab, onTab }) {
  const items = [
    { key: "home", label: "\u0413\u043B\u0430\u0432\u043D\u0430\u044F", icon: "house" },
    { key: "guide", label: "\u0417\u0430\u044F\u0432\u043A\u0430", icon: "list-checks" },
    { key: "catalog", label: "\u0421\u043A\u043B\u0430\u0434", icon: "boxes" },
    { key: "search", label: "\u041F\u043E\u0438\u0441\u043A", icon: "search" }
  ];
  return /* @__PURE__ */ React.createElement("nav", { style: {
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    zIndex: 30,
    background: "rgba(28,16,8,0.92)",
    backdropFilter: "blur(14px)",
    WebkitBackdropFilter: "blur(14px)",
    borderTop: "1px solid var(--line)",
    display: "grid",
    gridTemplateColumns: "repeat(4,1fr)",
    padding: "8px 6px calc(8px + env(safe-area-inset-bottom))"
  } }, items.map((it) => {
    const on = tab === it.key;
    return /* @__PURE__ */ React.createElement("button", { key: it.key, onClick: () => onTab(it.key), style: {
      background: "none",
      border: "none",
      cursor: "pointer",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 4,
      padding: "6px 0",
      color: on ? "var(--gold)" : "var(--cream-mute)"
    } }, /* @__PURE__ */ React.createElement(Icon, { name: it.icon, size: 22, strokeWidth: on ? 2.4 : 2 }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 10.5, fontWeight: on ? 700 : 500, letterSpacing: ".04em" } }, it.label));
  }));
}
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
function Sidebar({ tab, onTab }) {
  const items = [
    { key: "home", label: "\u0413\u043B\u0430\u0432\u043D\u0430\u044F", icon: "house" },
    { key: "guide", label: "\u041A\u0430\u043A \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0437\u0430\u044F\u0432\u043A\u0443", icon: "list-checks" },
    { key: "catalog", label: "\u0427\u0442\u043E \u0435\u0441\u0442\u044C \u043D\u0430 \u0441\u043A\u043B\u0430\u0434\u0435", icon: "boxes" },
    { key: "search", label: "\u041F\u043E\u0438\u0441\u043A", icon: "search" }
  ];
  return /* @__PURE__ */ React.createElement("aside", { style: {
    width: 264,
    flex: "0 0 auto",
    background: "var(--choc-900)",
    borderRight: "1px solid var(--line)",
    display: "flex",
    flexDirection: "column",
    padding: "26px 18px"
  } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/logos/yahya-logo-gold.png", alt: "YAHYA", style: { height: 30, alignSelf: "flex-start", marginLeft: 8, marginBottom: 6 } }), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, letterSpacing: ".16em", textTransform: "uppercase", color: "var(--cream-mute)", marginLeft: 8, marginBottom: 26 } }, "\u0421\u043A\u043B\u0430\u0434 \u0425\u041E\u0417"), /* @__PURE__ */ React.createElement("nav", { style: { display: "flex", flexDirection: "column", gap: 6 } }, items.map((it) => {
    const on = tab === it.key;
    return /* @__PURE__ */ React.createElement(
      "button",
      {
        key: it.key,
        onClick: () => onTab(it.key),
        style: {
          display: "flex",
          alignItems: "center",
          gap: 13,
          textAlign: "left",
          cursor: "pointer",
          padding: "12px 14px",
          borderRadius: 13,
          border: "none",
          background: on ? "var(--gold)" : "transparent",
          color: on ? "var(--choc-900)" : "var(--cream-dim)",
          fontFamily: "var(--font-sans)",
          fontSize: 14,
          fontWeight: on ? 700 : 600,
          letterSpacing: ".01em",
          transition: "background .15s ease, color .15s ease"
        },
        onMouseEnter: (e) => {
          if (!on) e.currentTarget.style.background = "var(--choc-700)";
        },
        onMouseLeave: (e) => {
          if (!on) e.currentTarget.style.background = "transparent";
        }
      },
      /* @__PURE__ */ React.createElement(Icon, { name: it.icon, size: 20, strokeWidth: on ? 2.4 : 2 }),
      it.label
    );
  })), /* @__PURE__ */ React.createElement("div", { style: { marginTop: "auto", fontSize: 11.5, color: "var(--cream-mute)", lineHeight: 1.5, marginLeft: 8 } }, "\u0421\u043A\u043B\u0430\u0434 \u0418\u0431\u0440\u0430\u0438\u043C\u043E\u0432\u0430 \xB7 \u0411\u0438\u0448\u043A\u0435\u043A", /* @__PURE__ */ React.createElement("br", null), "\u0412\u043D\u0443\u0442\u0440\u0435\u043D\u043D\u0438\u0439 \u0441\u043F\u0440\u0430\u0432\u043E\u0447\u043D\u0438\u043A YAHYA"));
}
Object.assign(window, { Icon, RecBadge, RegBadge, Chip, Btn, TopBar, BottomNav, Sidebar, useIsDesktop });
// ---- Home.jsx ----
function Home({ items, onTab, onPart, onSearch, wide }) {
  const counts = {};
  items.forEach((it) => {
    counts[it.part] = (counts[it.part] || 0) + 1;
  });
  const tileColor = {
    posuda: ["#caa86a", "rgba(202,168,106,0.14)"],
    hoz: ["#a9c178", "rgba(169,193,120,0.14)"],
    syrye: ["#e0b08a", "rgba(224,176,138,0.14)"],
    upakovka: ["#cf9f6a", "rgba(207,159,106,0.14)"],
    oborud: ["#bdb0a0", "rgba(189,176,160,0.14)"]
  };
  return /* @__PURE__ */ React.createElement("div", { className: "fade-in", style: wide ? { maxWidth: 1060, margin: "0 auto", padding: "14px 10px 0" } : null }, /* @__PURE__ */ React.createElement("div", { style: { padding: "26px 20px 18px", borderRadius: wide ? 22 : 0, background: "linear-gradient(180deg, #36230f, var(--app-bg))" } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/logos/yahya-logo-gold.png", alt: "YAHYA", style: { height: 34, display: "block", marginBottom: 22 } }), /* @__PURE__ */ React.createElement("div", { className: "eyebrow", style: { marginBottom: 10 } }, "\u0421\u043A\u043B\u0430\u0434 \u0418\u0431\u0440\u0430\u0438\u043C\u043E\u0432\u0430 \xB7 \u0425\u041E\u0417"), /* @__PURE__ */ React.createElement("h1", { className: "h-screen", style: { fontSize: wide ? 34 : 27, lineHeight: 1.12 } }, "\u0417\u0430\u044F\u0432\u043A\u0438 \u043D\u0430 \u0441\u043A\u043B\u0430\u0434 \u0425\u041E\u0417"), /* @__PURE__ */ React.createElement("p", { style: { color: "var(--cream-dim)", fontSize: 14.5, margin: "12px 0 0", maxWidth: 320 } }, "\u041D\u0430\u0443\u0447\u0438\u0441\u044C \u0437\u0430\u043A\u0430\u0437\u044B\u0432\u0430\u0442\u044C \u043F\u0440\u0430\u0432\u0438\u043B\u044C\u043D\u043E \u0437\u0430 5 \u043C\u0438\u043D\u0443\u0442 \u2014 \u0447\u0442\u043E \u0435\u0441\u0442\u044C \u043D\u0430 \u0441\u043A\u043B\u0430\u0434\u0435 \u0438 \u043A\u0430\u043A \u044D\u0442\u043E \u0437\u0430\u043A\u0430\u0437\u044B\u0432\u0430\u0442\u044C."), /* @__PURE__ */ React.createElement("button", { onClick: onSearch, style: {
    marginTop: 18,
    width: "100%",
    display: "flex",
    alignItems: "center",
    gap: 11,
    background: "var(--choc-800)",
    border: "1px solid var(--line-strong)",
    borderRadius: 14,
    padding: "13px 15px",
    cursor: "pointer",
    color: "var(--cream-mute)",
    fontSize: 14.5,
    fontFamily: "var(--font-sans)"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "search", size: 19, color: "var(--gold)" }), "\u041F\u043E\u0438\u0441\u043A \u043F\u043E \u0441\u043A\u043B\u0430\u0434\u0443\u2026")), /* @__PURE__ */ React.createElement("div", { style: { padding: "6px 20px 0", display: "grid", gap: 12, gridTemplateColumns: wide ? "1fr 1fr" : "1fr" } }, /* @__PURE__ */ React.createElement(
    BigEntry,
    {
      icon: "list-checks",
      title: "\u041A\u0430\u043A \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0437\u0430\u044F\u0432\u043A\u0443",
      desc: "\u041F\u043E\u0448\u0430\u0433\u043E\u0432\u044B\u0439 \u0433\u0430\u0439\u0434 \u0432 1\u0421 \u2014 6 \u043F\u0440\u043E\u0441\u0442\u044B\u0445 \u0448\u0430\u0433\u043E\u0432",
      tone: "gold",
      onClick: () => onTab("guide")
    }
  ), /* @__PURE__ */ React.createElement(
    BigEntry,
    {
      icon: "boxes",
      title: "\u0427\u0442\u043E \u0435\u0441\u0442\u044C \u043D\u0430 \u0441\u043A\u043B\u0430\u0434\u0435",
      desc: items.length + " \u043F\u043E\u0437\u0438\u0446\u0438\u0439 \u0441 \u0444\u043E\u0442\u043E \u0438 \u043F\u0440\u0430\u0432\u0438\u043B\u0430\u043C\u0438 \u0437\u0430\u043A\u0430\u0437\u0430",
      tone: "plain",
      onClick: () => onTab("catalog")
    }
  )), /* @__PURE__ */ React.createElement("div", { style: { padding: "22px 20px 8px" } }, /* @__PURE__ */ React.createElement("div", { className: "eyebrow", style: { marginBottom: 12 } }, "\u0427\u0430\u0441\u0442\u0438 \u0441\u043A\u043B\u0430\u0434\u0430"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: wide ? "repeat(3, 1fr)" : "1fr 1fr", gap: 11 } }, window.WH.PARTS.map((p, i) => {
    const [fg, bg] = tileColor[p.key];
    const full = !wide && p.key === "oborud";
    return /* @__PURE__ */ React.createElement("button", { key: p.key, onClick: () => onPart(p.key), className: "row-tap", style: {
      gridColumn: full ? "1 / -1" : "auto",
      display: "flex",
      alignItems: "center",
      gap: 12,
      textAlign: "left",
      background: "var(--choc-700)",
      border: "1px solid var(--line)",
      borderRadius: 16,
      padding: "14px 14px",
      cursor: "pointer"
    } }, /* @__PURE__ */ React.createElement("span", { style: {
      width: 42,
      height: 42,
      borderRadius: 12,
      background: bg,
      color: fg,
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      flex: "0 0 auto"
    } }, /* @__PURE__ */ React.createElement(Icon, { name: p.icon, size: 22 })), /* @__PURE__ */ React.createElement("span", { style: { minWidth: 0 } }, /* @__PURE__ */ React.createElement("span", { style: { display: "block", fontSize: 14.5, fontWeight: 700, color: "var(--cream)" } }, p.chip), /* @__PURE__ */ React.createElement("span", { style: { display: "block", fontSize: 12, color: "var(--cream-mute)" } }, p.name, " \xB7 ", counts[p.key] || 0, " \u043F\u043E\u0437.")));
  }))), /* @__PURE__ */ React.createElement("div", { style: { height: 16 } }));
}
function BigEntry({ icon, title, desc, tone, onClick }) {
  const gold = tone === "gold";
  return /* @__PURE__ */ React.createElement("button", { onClick, className: "row-tap", style: {
    display: "flex",
    alignItems: "center",
    gap: 15,
    textAlign: "left",
    cursor: "pointer",
    background: gold ? "linear-gradient(105deg, #d2a862, #b98e48)" : "var(--choc-700)",
    border: gold ? "none" : "1px solid var(--line-strong)",
    borderRadius: 18,
    padding: "18px 18px"
  } }, /* @__PURE__ */ React.createElement("span", { style: {
    width: 52,
    height: 52,
    borderRadius: 14,
    flex: "0 0 auto",
    background: gold ? "rgba(34,20,9,0.16)" : "rgba(210,168,98,0.14)",
    color: gold ? "var(--choc-900)" : "var(--gold)",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: icon, size: 27 })), /* @__PURE__ */ React.createElement("span", { style: { flex: 1, minWidth: 0 } }, /* @__PURE__ */ React.createElement("span", { style: {
    display: "block",
    fontSize: 17,
    fontWeight: 800,
    letterSpacing: ".02em",
    textTransform: "uppercase",
    color: gold ? "var(--choc-900)" : "var(--cream)"
  } }, title), /* @__PURE__ */ React.createElement("span", { style: {
    display: "block",
    fontSize: 13,
    marginTop: 3,
    color: gold ? "rgba(34,20,9,0.7)" : "var(--cream-mute)"
  } }, desc)), /* @__PURE__ */ React.createElement(Icon, { name: "arrow-right", size: 22, color: gold ? "var(--choc-900)" : "var(--gold)" }));
}
window.Home = Home;
// ---- Guide.jsx ----
function Guide({ onTab, onPart, wide }) {
  const [step, setStep] = React.useState(0);
  const [zoom, setZoom] = React.useState(null);
  const scrollRef = React.useRef(null);
  const steps = [
    {
      img: "step-1.png",
      title: "\u041E\u0442\u043A\u0440\u043E\u0439 \xAB\u0417\u0430\u044F\u0432\u043A\u0443 \u043D\u0430 \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u0438\u0435\xBB",
      body: "\u0412 1\u0421 \u0432\u0432\u0435\u0440\u0445\u0443 \u0432\u044B\u0431\u0435\u0440\u0438 \u0440\u0430\u0437\u0434\u0435\u043B \xAB\u0421\u043A\u043B\u0430\u0434\xBB. \u0412 \xAB\u0421\u0445\u0435\u043C\u0435 \u0440\u0430\u0431\u043E\u0442\u044B\xBB \u043D\u0430\u0436\u043C\u0438 \xAB\u0417\u0430\u044F\u0432\u043A\u0430 \u043D\u0430 \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u0438\u0435\xBB.",
      tip: { kind: "warn", text: "\u041D\u0435 \u043F\u0435\u0440\u0435\u043F\u0443\u0442\u0430\u0439: \u043D\u0443\u0436\u043D\u0430 \u0438\u043C\u0435\u043D\u043D\u043E \xAB\u0417\u0430\u044F\u0432\u043A\u0430 \u043D\u0430 \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u0438\u0435\xBB, \u0430 \u043D\u0435 \xAB\u041F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u0438\u0435 \u0442\u043E\u0432\u0430\u0440\u043E\u0432\xBB \u0438\u043B\u0438 \xAB\u0414\u0432\u0438\u0436\u0435\u043D\u0438\u0435 \u041C\u0411\u041F\xBB." }
    },
    {
      img: "step-2.png",
      title: "\u0421\u043E\u0437\u0434\u0430\u0439 \u043D\u043E\u0432\u044B\u0439 \u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442",
      body: "\u041E\u0442\u043A\u0440\u043E\u0435\u0442\u0441\u044F \u0441\u043F\u0438\u0441\u043E\u043A \u0437\u0430\u044F\u0432\u043E\u043A. \u041D\u0430\u0436\u043C\u0438 \u0437\u0435\u043B\u0451\u043D\u044B\u0439 \xAB+\xBB (\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C) \u0432 \u043F\u0430\u043D\u0435\u043B\u0438 \u0441\u0432\u0435\u0440\u0445\u0443 \u2014 \u0441\u043E\u0437\u0434\u0430\u0441\u0442\u0441\u044F \u043D\u043E\u0432\u0430\u044F \u043F\u0443\u0441\u0442\u0430\u044F \u0437\u0430\u044F\u0432\u043A\u0430."
    },
    {
      img: "step-3.png",
      title: "\u0417\u0430\u043F\u043E\u043B\u043D\u0438 \xAB\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044C\xBB \u0438 \xAB\u041F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u044C\xBB",
      body: "\u0412 \u0448\u0430\u043F\u043A\u0435 \u0437\u0430\u044F\u0432\u043A\u0438 \u0434\u0432\u0430 \u0433\u043B\u0430\u0432\u043D\u044B\u0445 \u043F\u043E\u043B\u044F. \u041E\u0440\u0433\u0430\u043D\u0438\u0437\u0430\u0446\u0438\u044F \u0443\u0436\u0435 \u0437\u0430\u043F\u043E\u043B\u043D\u0435\u043D\u0430. \u041D\u0430\u0436\u043C\u0438 \xAB\u2026\xBB \u0432 \u043F\u043E\u043B\u0435 \xAB\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044C\xBB (\u043E\u0442\u043A\u0443\u0434\u0430 \u0431\u0435\u0440\u0451\u043C \u0442\u043E\u0432\u0430\u0440), \u0437\u0430\u0442\u0435\u043C \u0432 \xAB\u041F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u044C\xBB (\u043A\u0443\u0434\u0430 \u043F\u0440\u0438\u0434\u0451\u0442).",
      tip: { kind: "info", text: "\u0421\u0442\u043E\u043B\u0431\u0446\u044B \xAB\u0426\u0435\u043D\u0430\xBB \u0438 \xAB\u0421\u0443\u043C\u043C\u0430\xBB \u0437\u0430\u043F\u043E\u043B\u043D\u044F\u0442\u044C \u043D\u0435 \u043D\u0443\u0436\u043D\u043E." }
    },
    {
      img: "step-4.png",
      title: "\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044C \u2014 \u0441\u043A\u043B\u0430\u0434 \u0418\u0431\u0440\u0430\u0438\u043C\u043E\u0432\u0430",
      body: "\u0412 \u043E\u043A\u043D\u0435 \xAB\u0421\u043A\u043B\u0430\u0434\u044B\xBB \u043E\u0442\u043A\u0440\u043E\u0439 \u043F\u0430\u043F\u043A\u0443 \xAB\u0418\u0431\u0440\u0430\u0438\u043C\u043E\u0432\u0430 249\xBB \u0438 \u0432\u044B\u0431\u0435\u0440\u0438 \u0441\u043A\u043B\u0430\u0434, \u0433\u0434\u0435 \u043B\u0435\u0436\u0438\u0442 \u043D\u0443\u0436\u043D\u044B\u0439 \u0442\u043E\u0432\u0430\u0440:",
      list: [
        ["\u042D\u043C\u0438\u043B\u044C \u2026 \u041C\u0411\u041F", "\u043F\u043E\u0441\u0443\u0434\u0430, \u043E\u0431\u043E\u0440\u0443\u0434\u043E\u0432\u0430\u043D\u0438\u0435"],
        ["\u042D\u043C\u0438\u043B\u044C \u2026 \u043F\u0440\u043E\u0447\u0435\u0435", "\u0445\u043E\u0437. \u0442\u043E\u0432\u0430\u0440\u044B"],
        ["\u042D\u043C\u0438\u043B\u044C \u2026 \u0421\u044B\u0440\u044C\u0451", "\u043C\u043E\u043B\u043E\u043A\u043E, \u0441\u0438\u0440\u043E\u043F\u044B, \u0441\u043E\u043A\u0438, \u0447\u0430\u0439"],
        ["\u042D\u043C\u0438\u043B\u044C \u2026 \u0423\u043F\u0430\u043A\u043E\u0432\u043A\u0430", "\u0441\u0442\u0430\u043A\u0430\u043D\u044B, \u043A\u0440\u044B\u0448\u043A\u0438, \u043F\u0430\u043A\u0435\u0442\u044B, \u043A\u043E\u0440\u043E\u0431\u043A\u0438"]
      ]
    },
    {
      img: "step-5.png",
      title: "\u041F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u044C \u2014 \u0442\u0432\u043E\u0439 \u0444\u0438\u043B\u0438\u0430\u043B",
      body: "\u041E\u0442\u043A\u0440\u043E\u0439 \u043F\u0430\u043F\u043A\u0443 \u0441\u0432\u043E\u0435\u0433\u043E \u0444\u0438\u043B\u0438\u0430\u043B\u0430 (\u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \xAB\u0421\u043A\u043B\u0430\u0434 \u0410\u0437\u0438\u044F \u043C\u043E\u043B\u043B\xBB) \u0438 \u0432\u044B\u0431\u0435\u0440\u0438, \u043A\u0443\u0434\u0430 \u043F\u0440\u0438\u0434\u0451\u0442 \u0442\u043E\u0432\u0430\u0440:",
      hint2: true
    },
    {
      img: "step-6.png",
      title: "\u0414\u043E\u0431\u0430\u0432\u044C \u0442\u043E\u0432\u0430\u0440 \u2014 \u0432\u044B\u0431\u0435\u0440\u0438 \u0442\u0438\u043F \u0434\u0430\u043D\u043D\u044B\u0445",
      body: "\u0414\u043E\u0431\u0430\u0432\u044C \u0441\u0442\u0440\u043E\u043A\u0443 \u0432 \u0442\u0430\u0431\u043B\u0438\u0446\u0443. 1\u0421 \u0441\u043F\u0440\u043E\u0441\u0438\u0442 \xAB\u0412\u044B\u0431\u043E\u0440 \u0442\u0438\u043F\u0430 \u0434\u0430\u043D\u043D\u044B\u0445\xBB. \u0422\u0438\u043F \u0437\u0430\u0432\u0438\u0441\u0438\u0442 \u043E\u0442 \u043F\u043E\u0437\u0438\u0446\u0438\u0438 \u0438 \u0443\u043A\u0430\u0437\u0430\u043D \u0432 \u0435\u0451 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0435 \u0432 \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0435:",
      regHint: true,
      cta: { label: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u043A\u0430\u0442\u0430\u043B\u043E\u0433", to: "catalog" },
      tip: { kind: "info", text: "\u0411\u0435\u0440\u0438 \u0442\u043E\u0447\u043D\u043E\u0435 \u043D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0438\u0437 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0438 (\u043A\u043D\u043E\u043F\u043A\u0430 \xAB\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043D\u0430\u0437\u0432\u0430\u043D\u0438\u0435\xBB) \u2014 \u043D\u0430\u0439\u0434\u0451\u0448\u044C \u043F\u043E\u0437\u0438\u0446\u0438\u044E \u0431\u0435\u0437 \u043E\u0448\u0438\u0431\u043E\u043A." }
    },
    {
      img: "step-7.png",
      title: "\u041A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E, \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0430, \u041E\u041A",
      body: "\u0412\u043F\u0438\u0448\u0438 \xAB\u041A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E\xBB \u0447\u0438\u0441\u043B\u043E\u043C. \u0412 \xAB\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439\xBB \u2014 \u0435\u0434\u0438\u043D\u0438\u0446\u0443 \u0438\u043B\u0438 \u0444\u0430\u0441\u043E\u0432\u043A\u0443 \u043F\u043E \u043F\u043E\u0437\u0438\u0446\u0438\u0438: \u0448\u0442, \u043A\u0433, \u043B, \xAB1 \u0440\u0443\u043A\u0430\u0432\xBB, \xAB1 \u043F\u0430\u0447\u043A\u0430\xBB (\u0441\u043C\u043E\u0442\u0440\u0438 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0443 \u0442\u043E\u0432\u0430\u0440\u0430). \u0421\u0432\u0435\u0440\u044C \u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044F/\u041F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u044F \u0438 \u043D\u0430\u0436\u043C\u0438 \xAB\u041E\u041A\xBB / \xAB\u0417\u0430\u043F\u0438\u0441\u0430\u0442\u044C\xBB.",
      example: true,
      done: true
    }
  ];
  const s = steps[step];
  const last = step === steps.length - 1;
  const go = (d) => {
    setStep((x) => Math.min(steps.length - 1, Math.max(0, x + d)));
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };
  const imgSrc = "./assets/warehouse/guide/" + s.img;
  return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", height: "100%" } }, /* @__PURE__ */ React.createElement(
    TopBar,
    {
      title: "\u041A\u0430\u043A \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0437\u0430\u044F\u0432\u043A\u0443",
      subtitle: "\u0428\u0430\u0433 " + (step + 1) + " \u0438\u0437 " + steps.length,
      onBack: step > 0 ? () => go(-1) : () => onTab("home")
    }
  ), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 5, padding: "12px 18px 4px", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0", width: "100%", boxSizing: "border-box" } }, steps.map((_, i) => /* @__PURE__ */ React.createElement("div", { key: i, style: {
    flex: 1,
    height: 5,
    borderRadius: 999,
    background: i <= step ? "var(--gold)" : "var(--choc-600)",
    transition: "background .25s ease"
  } }))), /* @__PURE__ */ React.createElement("div", { ref: scrollRef, className: "scroll", style: { paddingBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { key: step, className: "fade-in", style: { padding: "16px 20px 0", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0" } }, /* @__PURE__ */ React.createElement("button", { onClick: () => setZoom(imgSrc), "aria-label": "\u0423\u0432\u0435\u043B\u0438\u0447\u0438\u0442\u044C \u0441\u043A\u0440\u0438\u043D\u0448\u043E\u0442", style: {
    display: "block",
    width: "100%",
    padding: 8,
    marginBottom: 18,
    cursor: "zoom-in",
    background: "var(--choc-900)",
    border: "1px solid var(--line-strong)",
    borderRadius: 18,
    position: "relative"
  } }, /* @__PURE__ */ React.createElement("img", { src: imgSrc, alt: "\u0428\u0430\u0433 " + (step + 1), style: {
    display: "block",
    width: "100%",
    maxHeight: wide ? 380 : "44vh",
    objectFit: "contain",
    borderRadius: 11,
    background: "#1d1109"
  } }), /* @__PURE__ */ React.createElement("span", { style: {
    position: "absolute",
    left: 14,
    top: 14,
    fontSize: 12,
    fontWeight: 800,
    color: "var(--choc-900)",
    background: "var(--gold)",
    borderRadius: 8,
    padding: "3px 9px"
  } }, "\u0428\u0430\u0433 ", step + 1), /* @__PURE__ */ React.createElement("span", { style: {
    position: "absolute",
    right: 14,
    bottom: 14,
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    fontSize: 11.5,
    fontWeight: 600,
    color: "var(--cream-dim)",
    background: "rgba(28,16,8,0.82)",
    border: "1px solid var(--line)",
    borderRadius: 999,
    padding: "5px 10px"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "expand", size: 13, color: "var(--gold)" }), "\u0443\u0432\u0435\u043B\u0438\u0447\u0438\u0442\u044C")), /* @__PURE__ */ React.createElement("h2", { className: "h-screen", style: { fontSize: 22 } }, s.title), /* @__PURE__ */ React.createElement("p", { style: { color: "var(--cream-dim)", fontSize: 15.5, lineHeight: 1.55, margin: "10px 0 0" } }, s.body), s.list && /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gap: 9, marginTop: 18 } }, s.list.map(([h, d], i) => /* @__PURE__ */ React.createElement("div", { key: i, className: "card", style: { padding: "13px 14px", display: "flex", gap: 11, alignItems: "center" } }, /* @__PURE__ */ React.createElement(Icon, { name: "folder", size: 20, color: "var(--gold)" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14.5, fontWeight: 700, color: "var(--cream)" } }, h), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12.5, color: "var(--cream-mute)" } }, d))))), s.hint2 && /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 18 } }, /* @__PURE__ */ React.createElement("div", { style: { background: "var(--bar-bg)", border: "1px solid rgba(216,166,87,0.35)", borderRadius: 14, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { className: "badge bar", style: { marginBottom: 8 } }, /* @__PURE__ */ React.createElement(Icon, { name: "coffee", size: 12 }), "\u0411\u0430\u0440 \u0426\u0423\u041C"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 } }, "\u0415\u0441\u043B\u0438 \u0442\u043E\u0432\u0430\u0440 \u0434\u043B\u044F \u0431\u0430\u0440-\u0437\u043E\u043D\u044B")), /* @__PURE__ */ React.createElement("div", { style: { background: "var(--mag-bg)", border: "1px solid rgba(169,193,120,0.35)", borderRadius: 14, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { className: "badge mag", style: { marginBottom: 8 } }, /* @__PURE__ */ React.createElement(Icon, { name: "store", size: 12 }), "\u041C\u0430\u0433\u0430\u0437\u0438\u043D \u0426\u0423\u041C"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 } }, "\u0415\u0441\u043B\u0438 \u0442\u043E\u0432\u0430\u0440 \u0434\u043B\u044F \u043C\u0430\u0433\u0430\u0437\u0438\u043D\u0430"))), s.regHint && /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gap: 10, marginTop: 18 } }, /* @__PURE__ */ React.createElement("div", { style: { background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: 14, display: "flex", gap: 12, alignItems: "center" } }, /* @__PURE__ */ React.createElement("span", { className: "badge oba" }, /* @__PURE__ */ React.createElement(Icon, { name: "list-tree", size: 12 }), "\u041D\u043E\u043C\u0435\u043D\u043A\u043B\u0430\u0442\u0443\u0440\u0430"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 } }, "\u0431\u043E\u043B\u044C\u0448\u0438\u043D\u0441\u0442\u0432\u043E \u043F\u043E\u0437\u0438\u0446\u0438\u0439 \u0441\u043A\u043B\u0430\u0434\u0430")), /* @__PURE__ */ React.createElement("div", { style: { background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: 14, display: "flex", gap: 12, alignItems: "center" } }, /* @__PURE__ */ React.createElement("span", { className: "badge mag" }, /* @__PURE__ */ React.createElement(Icon, { name: "package", size: 12 }), "\u0422\u043E\u0432\u0430\u0440\u044B"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 } }, "\u0447\u0430\u0441\u0442\u044C \u0443\u043F\u0430\u043A\u043E\u0432\u043A\u0438 \u0438 \u0440\u043E\u0437\u043D\u0438\u0447\u043D\u044B\u0445 \u043F\u043E\u0437\u0438\u0446\u0438\u0439")), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12.5, color: "var(--cream-mute)", lineHeight: 1.45, padding: "0 2px" } }, "\u0422\u043E\u0447\u043D\u044B\u0439 \u0442\u0438\u043F \u0434\u043B\u044F \u043A\u0430\u0436\u0434\u043E\u0439 \u043F\u043E\u0437\u0438\u0446\u0438\u0438 \u043D\u0430\u043F\u0438\u0441\u0430\u043D \u0432 \u0435\u0451 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0435 \u0432 \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0435.")), s.example && /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginTop: 18, padding: 0, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 13, padding: 14, alignItems: "center" } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/warehouse/upakovka-007.jpg", alt: "", style: { width: 64, height: 64, objectFit: "cover", borderRadius: 12, flex: "0 0 auto" } }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14, fontWeight: 700, color: "var(--cream)", lineHeight: 1.3 } }, "\u0421\u0442\u0430\u043A\u0430\u043D \u0431\u0443\u043C\u0430\u0436\u043D\u044B\u0439 350 \u043C\u043B"), /* @__PURE__ */ React.createElement("div", { className: "badge bar", style: { marginTop: 6 } }, /* @__PURE__ */ React.createElement(Icon, { name: "coffee", size: 12 }), "\u0411\u0430\u0440"))), /* @__PURE__ */ React.createElement("div", { style: { borderTop: "1px solid var(--line)", display: "grid", gridTemplateColumns: "1fr 1fr" } }, /* @__PURE__ */ React.createElement("div", { style: { padding: "12px 14px", borderRight: "1px solid var(--line)" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" } }, "\u041A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 15, fontWeight: 700, color: "var(--cream)", marginTop: 3 } }, "1")), /* @__PURE__ */ React.createElement("div", { style: { padding: "12px 14px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" } }, "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 15, fontWeight: 700, color: "var(--gold)", marginTop: 3 } }, "1 \u0440\u0443\u043A\u0430\u0432 (27 \u0448\u0442)")))), s.tip && /* @__PURE__ */ React.createElement("div", { style: {
    marginTop: 18,
    display: "flex",
    gap: 10,
    background: s.tip.kind === "warn" ? "rgba(224,138,106,0.12)" : "rgba(210,168,98,0.1)",
    border: "1px solid " + (s.tip.kind === "warn" ? "rgba(224,138,106,0.34)" : "rgba(210,168,98,0.28)"),
    borderRadius: 13,
    padding: "12px 14px"
  } }, /* @__PURE__ */ React.createElement(
    Icon,
    {
      name: s.tip.kind === "warn" ? "alert-triangle" : "info",
      size: 18,
      color: s.tip.kind === "warn" ? "var(--add)" : "var(--gold)",
      style: { marginTop: 1, flex: "0 0 auto" }
    }
  ), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13.5, color: "var(--cream-dim)", lineHeight: 1.45 } }, s.tip.text)), s.cta && /* @__PURE__ */ React.createElement("button", { onClick: () => onTab(s.cta.to), style: {
    marginTop: 16,
    width: "100%",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    background: "var(--choc-700)",
    border: "1px solid var(--line-strong)",
    borderRadius: 13,
    padding: "13px 15px",
    cursor: "pointer",
    color: "var(--cream)",
    fontSize: 14,
    fontWeight: 600
  } }, /* @__PURE__ */ React.createElement("span", { style: { display: "inline-flex", alignItems: "center", gap: 9 } }, /* @__PURE__ */ React.createElement(Icon, { name: "boxes", size: 18, color: "var(--gold)" }), s.cta.label), /* @__PURE__ */ React.createElement(Icon, { name: "arrow-right", size: 18, color: "var(--gold)" })), s.done && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 18, textAlign: "center", padding: "10px 0 4px" } }, /* @__PURE__ */ React.createElement("div", { style: {
    width: 64,
    height: 64,
    borderRadius: 999,
    margin: "0 auto 12px",
    background: "rgba(159,192,106,0.18)",
    color: "var(--ok)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "check", size: 34, strokeWidth: 3 })), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 17, fontWeight: 800, textTransform: "uppercase", letterSpacing: ".04em", color: "var(--cream)" } }, "\u0413\u043E\u0442\u043E\u0432\u043E!"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13.5, color: "var(--cream-mute)", marginTop: 4 } }, "\u0422\u0435\u043F\u0435\u0440\u044C \u0442\u044B \u0443\u043C\u0435\u0435\u0448\u044C \u0441\u043E\u0437\u0434\u0430\u0432\u0430\u0442\u044C \u0437\u0430\u044F\u0432\u043A\u0438.")))), /* @__PURE__ */ React.createElement("div", { style: {
    padding: "12px 20px calc(14px + env(safe-area-inset-bottom))",
    borderTop: "1px solid var(--line)",
    display: "flex",
    gap: 10,
    background: "var(--choc-900)",
    maxWidth: wide ? 680 : "none",
    margin: wide ? "0 auto" : "0",
    width: "100%",
    boxSizing: "border-box"
  } }, step > 0 && /* @__PURE__ */ React.createElement(Btn, { variant: "ghost", icon: "chevron-left", onClick: () => go(-1), style: { flex: "0 0 auto", textTransform: "none", padding: "15px 16px" } }, "\u041D\u0430\u0437\u0430\u0434"), !last && /* @__PURE__ */ React.createElement(Btn, { variant: "primary", iconRight: "chevron-right", full: true, onClick: () => go(1) }, "\u0414\u0430\u043B\u044C\u0448\u0435"), last && /* @__PURE__ */ React.createElement(Btn, { variant: "primary", icon: "boxes", full: true, onClick: () => onTab("catalog") }, "\u041F\u0435\u0440\u0435\u0439\u0442\u0438 \u0432 \u043A\u0430\u0442\u0430\u043B\u043E\u0433")), zoom && /* @__PURE__ */ React.createElement("div", { onClick: () => setZoom(null), style: {
    position: "fixed",
    inset: 0,
    zIndex: 200,
    background: "rgba(0,0,0,0.92)",
    overflow: "auto",
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "center",
    padding: 12
  } }, /* @__PURE__ */ React.createElement("img", { src: zoom, alt: "", onClick: (e) => e.stopPropagation(), style: {
    display: "block",
    minWidth: "100%",
    width: "auto",
    height: "auto",
    maxWidth: "none",
    margin: "auto",
    borderRadius: 8
  } }), /* @__PURE__ */ React.createElement("button", { onClick: () => setZoom(null), "aria-label": "\u0417\u0430\u043A\u0440\u044B\u0442\u044C", style: {
    position: "fixed",
    right: 14,
    top: 14,
    width: 40,
    height: 40,
    borderRadius: 12,
    background: "rgba(28,16,8,0.9)",
    border: "1px solid var(--line-strong)",
    color: "var(--cream)",
    cursor: "pointer",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 201
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "x", size: 20 }))));
}
window.Guide = Guide;
// ---- Catalog.jsx ----
function Catalog({ items, initialPart, onOpen, onTab, wide }) {
  const [part, setPart] = React.useState(initialPart || "posuda");
  const [rec, setRec] = React.useState("all");
  const [section, setSection] = React.useState("all");
  React.useEffect(() => {
    if (initialPart) setPart(initialPart);
  }, [initialPart]);
  React.useEffect(() => {
    setSection("all");
    setRec("all");
  }, [part]);
  const partItems = items.filter((it) => it.part === part);
  const sections = [...new Set(partItems.map((it) => it.section).filter(Boolean))];
  const hasSections = sections.length > 1 || sections.length === 1 && sections[0] !== "";
  let shown = partItems;
  if (rec !== "all") shown = shown.filter((it) => it.rec.key === rec || rec !== "oba" && it.rec.key === "oba");
  if (section !== "all") shown = shown.filter((it) => it.section === section);
  const groups = section === "all" && hasSections ? window.WH.groupBySection(shown) : [["", shown]];
  const recFilters = [["all", "\u0412\u0441\u0435"], ["bar", "\u0411\u0430\u0440"], ["mag", "\u041C\u0430\u0433\u0430\u0437\u0438\u043D"], ["oba", "\u041E\u0431\u0430"]];
  return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", height: "100%" } }, /* @__PURE__ */ React.createElement(
    TopBar,
    {
      title: "\u0427\u0442\u043E \u0435\u0441\u0442\u044C \u043D\u0430 \u0441\u043A\u043B\u0430\u0434\u0435",
      onBack: wide ? void 0 : () => onTab("home"),
      right: /* @__PURE__ */ React.createElement("button", { onClick: () => onTab("search"), "aria-label": "\u041F\u043E\u0438\u0441\u043A", style: { background: "var(--choc-700)", border: "1px solid var(--line)", color: "var(--cream)", width: 38, height: 38, borderRadius: 11, display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer" } }, /* @__PURE__ */ React.createElement(Icon, { name: "search", size: 19 }))
    }
  ), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8, flexWrap: wide ? "wrap" : "nowrap", overflowX: wide ? "visible" : "auto", padding: "12px 16px 10px", borderBottom: "1px solid var(--line)" } }, window.WH.PARTS.map((p) => /* @__PURE__ */ React.createElement(Chip, { key: p.key, active: part === p.key, icon: p.icon, onClick: () => setPart(p.key) }, p.chip))), /* @__PURE__ */ React.createElement("div", { className: "scroll" }, /* @__PURE__ */ React.createElement("div", { style: { padding: "14px 16px 6px" } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between" } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, color: "var(--cream-mute)" } }, "\u041D\u0430\u0439\u0434\u0435\u043D\u043E ", /* @__PURE__ */ React.createElement("b", { style: { color: "var(--cream)" } }, shown.length), " \u043F\u043E\u0437."), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, color: "var(--cream-mute)" } }, window.WH.partOf(part).name))), /* @__PURE__ */ React.createElement("div", { style: { padding: "8px 16px 24px" } }, groups.map(([sec, list]) => /* @__PURE__ */ React.createElement("div", { key: sec || "_" }, sec && /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 9, margin: "16px 2px 11px" } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "var(--gold)" } }, sec), /* @__PURE__ */ React.createElement("span", { style: { height: 1, flex: 1, background: "var(--line)" } }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, color: "var(--cream-mute)" } }, list.length)), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: wide ? "repeat(auto-fill, minmax(190px, 1fr))" : "1fr 1fr", gap: wide ? 16 : 12 } }, list.map((it) => /* @__PURE__ */ React.createElement(Tile, { key: it.part + it.n, it, onOpen }))))), shown.length === 0 && /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center", color: "var(--cream-mute)", padding: "40px 0", fontSize: 14 } }, "\u041D\u0438\u0447\u0435\u0433\u043E \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E \u0432 \u044D\u0442\u043E\u043C \u0444\u0438\u043B\u044C\u0442\u0440\u0435."))));
}
function Tile({ it, onOpen }) {
  const reg = window.WH.regInfo(it);
  return /* @__PURE__ */ React.createElement("button", { onClick: () => onOpen(it), className: "row-tap card", style: {
    padding: 0,
    overflow: "hidden",
    cursor: "pointer",
    textAlign: "left",
    display: "flex",
    flexDirection: "column"
  } }, /* @__PURE__ */ React.createElement("div", { style: { aspectRatio: "1/1", background: "#fff", position: "relative" } }, /* @__PURE__ */ React.createElement(
    "img",
    {
      src: "./assets/warehouse/" + it.img,
      alt: "",
      loading: "lazy",
      style: { width: "100%", height: "100%", objectFit: "cover" }
    }
  ), /* @__PURE__ */ React.createElement("span", { style: { position: "absolute", top: 8, left: 8 } }, /* @__PURE__ */ React.createElement(RecBadge, { rec: it.rec, withIcon: false })), it.flag === "add" && /* @__PURE__ */ React.createElement("span", { style: { position: "absolute", top: 8, right: 8, width: 22, height: 22, borderRadius: 999, background: "rgba(224,138,106,0.92)", color: "#2a1a10", display: "inline-flex", alignItems: "center", justifyContent: "center" }, title: "\u041D\u0435\u0442 \u0432 \u0431\u0430\u0437\u0435 \u2014 \u0434\u043E\u0431\u0430\u0432\u0438\u0442\u044C" }, /* @__PURE__ */ React.createElement(Icon, { name: "plus", size: 13, strokeWidth: 3 }))), /* @__PURE__ */ React.createElement("div", { style: { padding: "10px 11px 12px", flex: 1, display: "flex", flexDirection: "column", gap: 6 } }, /* @__PURE__ */ React.createElement("span", { style: {
    fontSize: 13,
    fontWeight: 600,
    color: "var(--cream)",
    lineHeight: 1.3,
    display: "-webkit-box",
    WebkitLineClamp: 2,
    WebkitBoxOrient: "vertical",
    overflow: "hidden"
  } }, it.title), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 6, marginTop: "auto", flexWrap: "wrap" } }, /* @__PURE__ */ React.createElement(RegBadge, { reg, small: true }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11, color: "var(--cream-mute)" } }, it.unitLabel, it.pack ? " \xB7 " + it.pack.unitPack : ""))));
}
window.Catalog = Catalog;
// ---- ProductSheet.jsx ----
function ProductSheet({ it, onClose, desktop }) {
  const [copied, setCopied] = React.useState(false);
  const mounted = React.useRef(false);
  const [show, setShow] = React.useState(false);
  React.useEffect(() => {
    const t = setTimeout(() => setShow(true), 10);
    return () => clearTimeout(t);
  }, []);
  if (!it) return null;
  const copy = () => {
    const text = it.title;
    const done = () => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(done);
    else done();
  };
  const close = () => {
    setShow(false);
    setTimeout(onClose, 240);
  };
  const reg = window.WH.regInfo(it);
  const flagInfo = it.flag === "add" ? { c: "var(--add)", bg: "rgba(224,138,106,0.14)", icon: "plus-circle", t: "\u041D\u0435\u0442 \u0432 \u0431\u0430\u0437\u0435 \u2014 \u043D\u0443\u0436\u043D\u043E \u0434\u043E\u0431\u0430\u0432\u0438\u0442\u044C" } : it.flag === "check" ? { c: "var(--warn)", bg: "rgba(224,177,90,0.14)", icon: "alert-triangle", t: "\u0423\u0442\u043E\u0447\u043D\u0438\u0442\u044C \u0432\u0430\u0440\u0438\u0430\u043D\u0442 \u0432 \u0431\u0430\u0437\u0435" } : null;
  const panelStyle = desktop ? {
    position: "absolute",
    left: "50%",
    top: "50%",
    width: "min(480px, 92%)",
    maxHeight: "88%",
    background: "var(--choc-800)",
    borderRadius: 24,
    transform: show ? "translate(-50%, -50%) scale(1)" : "translate(-50%, -47%) scale(0.97)",
    opacity: show ? 1 : 0,
    transition: "transform .26s var(--ease-out), opacity .2s ease",
    display: "flex",
    flexDirection: "column",
    boxShadow: "0 26px 70px rgba(0,0,0,0.55)"
  } : {
    position: "absolute",
    left: 0,
    right: 0,
    bottom: 0,
    maxHeight: "94%",
    background: "var(--choc-800)",
    borderTopLeftRadius: 26,
    borderTopRightRadius: 26,
    transform: show ? "translateY(0)" : "translateY(100%)",
    transition: "transform .26s var(--ease-out)",
    display: "flex",
    flexDirection: "column",
    boxShadow: "0 -16px 50px rgba(0,0,0,0.5)"
  };
  return (
    // fixed (не absolute): прикрепляет лист к окну/iframe, а не к концу прокрутки.
    // У телефонной раскладки #app только min-height:100vh без definite height, поэтому
    // цепочка height:100% не резолвится и absolute-оверлей растягивался на всю высоту
    // контента — лист уезжал в самый низ. fixed считается от вьюпорта iframe.
    /* @__PURE__ */ React.createElement("div", { style: { position: "fixed", inset: 0, zIndex: 60 } }, /* @__PURE__ */ React.createElement("div", { onClick: close, style: {
      position: "absolute",
      inset: 0,
      background: "rgba(15,8,3,0.6)",
      opacity: show ? 1 : 0,
      transition: "opacity .24s ease"
    } }), /* @__PURE__ */ React.createElement("div", { style: panelStyle }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "center", padding: "10px 0 4px", position: "relative" } }, !desktop && /* @__PURE__ */ React.createElement("span", { style: { width: 40, height: 4, borderRadius: 999, background: "var(--line-strong)" } }), /* @__PURE__ */ React.createElement("button", { onClick: close, "aria-label": "\u0417\u0430\u043A\u0440\u044B\u0442\u044C", style: {
      position: "absolute",
      right: 14,
      top: 8,
      width: 34,
      height: 34,
      borderRadius: 10,
      background: "var(--choc-600)",
      border: "none",
      color: "var(--cream)",
      cursor: "pointer",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center"
    } }, /* @__PURE__ */ React.createElement(Icon, { name: "x", size: 18 }))), /* @__PURE__ */ React.createElement("div", { className: "scroll", style: { paddingBottom: 20 } }, /* @__PURE__ */ React.createElement("div", { style: { margin: "8px 16px 0", borderRadius: 18, overflow: "hidden", background: "#fff", aspectRatio: "4/3" } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/warehouse/" + it.img, alt: "", style: { width: "100%", height: "100%", objectFit: "cover" } })), /* @__PURE__ */ React.createElement("div", { style: { padding: "16px 18px 0" } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" } }, /* @__PURE__ */ React.createElement(RecBadge, { rec: it.rec }), /* @__PURE__ */ React.createElement(RegBadge, { reg }), /* @__PURE__ */ React.createElement("span", { className: "badge oba" }, /* @__PURE__ */ React.createElement(Icon, { name: "warehouse", size: 12 }), it.sklad)), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 6 } }, "\u0422\u043E\u0447\u043D\u043E\u0435 \u043D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0432 \u0431\u0430\u0437\u0435 1\u0421"), /* @__PURE__ */ React.createElement("div", { style: { background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: "14px 15px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 17, fontWeight: 700, color: "var(--cream)", lineHeight: 1.35 } }, it.title), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, color: "var(--cream-mute)" } }, it.code ? "\u043A\u043E\u0434 \u2026" + it.code : "\u043A\u043E\u0434 \u0443\u0442\u043E\u0447\u043D\u044F\u0435\u0442\u0441\u044F", it.draft && it.draft !== it.title ? " \xB7 \xAB" + it.draft + "\xBB" : "")), /* @__PURE__ */ React.createElement("button", { onClick: copy, style: {
      marginTop: 12,
      width: "100%",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 8,
      background: copied ? "rgba(159,192,106,0.18)" : "var(--gold)",
      color: copied ? "var(--ok)" : "var(--choc-900)",
      border: "none",
      borderRadius: 11,
      padding: "12px",
      fontWeight: 700,
      fontSize: 13,
      letterSpacing: ".06em",
      textTransform: "uppercase",
      cursor: "pointer",
      transition: "background .2s ease"
    } }, /* @__PURE__ */ React.createElement(Icon, { name: copied ? "check" : "copy", size: 16 }), copied ? "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u043D\u043E" : "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043D\u0430\u0437\u0432\u0430\u043D\u0438\u0435")), flagInfo && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 12, display: "flex", gap: 9, background: flagInfo.bg, borderRadius: 12, padding: "11px 13px" } }, /* @__PURE__ */ React.createElement(Icon, { name: flagInfo.icon, size: 17, color: flagInfo.c }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, color: "var(--cream-dim)" } }, flagInfo.t)), it.note && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 6 } }, "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435"), /* @__PURE__ */ React.createElement("p", { style: { fontSize: 13.5, color: "var(--cream-dim)", lineHeight: 1.5, margin: 0 } }, it.note)), /* @__PURE__ */ React.createElement("div", { style: { marginTop: 20, fontSize: 13, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "var(--gold)", marginBottom: 10 } }, "\u041A\u0430\u043A \u0437\u0430\u043A\u0430\u0437\u044B\u0432\u0430\u0442\u044C"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gap: 9 } }, /* @__PURE__ */ React.createElement(FieldRow, { icon: "ruler", label: "\u0415\u0434\u0438\u043D\u0438\u0446\u0430 \u0438\u0437\u043C\u0435\u0440\u0435\u043D\u0438\u044F", value: it.unitLabel }), it.pack ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(FieldRow, { icon: "boxes", label: "\u0424\u0430\u0441\u043E\u0432\u043A\u0430", value: it.pack.unitPack + " = " + it.pack.per + " \u0448\u0442" }), /* @__PURE__ */ React.createElement(FieldRow, { icon: "pencil", label: "\u0412 \u0437\u0430\u044F\u0432\u043A\u0435 \u043F\u0438\u0441\u0430\u0442\u044C", value: "\xAB" + it.pack.write + "\xBB", accent: true })) : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(FieldRow, { icon: "hash", label: "\u0417\u0430\u043A\u0430\u0437", value: "\u0428\u0442\u0443\u0447\u043D\u043E" }), /* @__PURE__ */ React.createElement(FieldRow, { icon: "pencil", label: "\u0412 \u0437\u0430\u044F\u0432\u043A\u0435 \u043F\u0438\u0441\u0430\u0442\u044C", value: "\u041A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E, \u043D\u0430\u043F\u0440. \xAB5\xBB" }))), it.pack && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 12, display: "flex", gap: 9, background: "rgba(210,168,98,0.1)", border: "1px solid rgba(210,168,98,0.26)", borderRadius: 12, padding: "11px 13px" } }, /* @__PURE__ */ React.createElement(Icon, { name: "info", size: 17, color: "var(--gold)" }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.45 } }, it.pack.hint))))))
  );
}
function FieldRow({ icon, label, value, accent }) {
  return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12, background: "var(--choc-700)", border: "1px solid var(--line)", borderRadius: 13, padding: "13px 14px" } }, /* @__PURE__ */ React.createElement("span", { style: { width: 34, height: 34, borderRadius: 9, background: "rgba(210,168,98,0.13)", color: "var(--gold)", display: "inline-flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" } }, /* @__PURE__ */ React.createElement(Icon, { name: icon, size: 17 })), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12.5, color: "var(--cream-mute)", flex: 1 } }, label), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 14.5, fontWeight: 700, color: accent ? "var(--gold)" : "var(--cream)", textAlign: "right" } }, value));
}
window.ProductSheet = ProductSheet;
// ---- Search.jsx ----
function Search({ items, onOpen, onTab, wide }) {
  const [q, setQ] = React.useState("");
  const inputRef = React.useRef(null);
  React.useEffect(() => {
    if (inputRef.current) inputRef.current.focus();
  }, []);
  const query = q.trim().toLowerCase();
  const results = query.length === 0 ? [] : items.filter((it) => {
    const hay = (it.title + " " + it.draft + " " + it.section + " " + it.code + " " + it.partName).toLowerCase();
    return query.split(/\s+/).every((w) => hay.includes(w));
  }).slice(0, 60);
  const suggestions = ["\u0441\u0442\u0430\u043A\u0430\u043D", "\u043C\u043E\u043B\u043E\u043A\u043E", "\u0441\u0438\u0440\u043E\u043F", "\u0442\u0430\u0440\u0435\u043B\u043A\u0430", "\u043A\u0440\u044B\u0448\u043A\u0430", "\u043F\u0430\u043A\u0435\u0442"];
  return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", height: "100%" } }, /* @__PURE__ */ React.createElement(TopBar, { title: "\u041F\u043E\u0438\u0441\u043A \u043F\u043E \u0441\u043A\u043B\u0430\u0434\u0443", onBack: () => onTab("home") }), /* @__PURE__ */ React.createElement("div", { style: { padding: "14px 16px 8px", maxWidth: wide ? 760 : "none", margin: wide ? "0 auto" : "0", width: "100%", boxSizing: "border-box" } }, /* @__PURE__ */ React.createElement("div", { style: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    background: "var(--choc-800)",
    border: "1px solid var(--line-strong)",
    borderRadius: 14,
    padding: "12px 14px"
  } }, /* @__PURE__ */ React.createElement(Icon, { name: "search", size: 19, color: "var(--gold)" }), /* @__PURE__ */ React.createElement(
    "input",
    {
      ref: inputRef,
      value: q,
      onChange: (e) => setQ(e.target.value),
      placeholder: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0438\u043B\u0438 \u043A\u043E\u0434\u2026",
      style: {
        flex: 1,
        background: "none",
        border: "none",
        outline: "none",
        color: "var(--cream)",
        fontFamily: "var(--font-sans)",
        fontSize: 15.5
      }
    }
  ), q && /* @__PURE__ */ React.createElement("button", { onClick: () => setQ(""), "aria-label": "\u041E\u0447\u0438\u0441\u0442\u0438\u0442\u044C", style: { background: "none", border: "none", color: "var(--cream-mute)", cursor: "pointer", display: "inline-flex" } }, /* @__PURE__ */ React.createElement(Icon, { name: "x", size: 18 })))), /* @__PURE__ */ React.createElement("div", { className: "scroll", style: wide ? { maxWidth: 760, margin: "0 auto", width: "100%" } : null }, query.length === 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: "10px 18px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 12 } }, "\u041F\u043E\u043F\u0443\u043B\u044F\u0440\u043D\u043E\u0435"), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexWrap: "wrap", gap: 8 } }, suggestions.map((s) => /* @__PURE__ */ React.createElement(Chip, { key: s, onClick: () => setQ(s) }, s)))), query.length > 0 && results.length === 0 && /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center", padding: "56px 30px 0", color: "var(--cream-mute)" } }, /* @__PURE__ */ React.createElement("div", { style: { width: 70, height: 70, borderRadius: 999, margin: "0 auto 16px", background: "var(--choc-700)", display: "flex", alignItems: "center", justifyContent: "center" } }, /* @__PURE__ */ React.createElement(Icon, { name: "search-x", size: 34, color: "var(--cream-mute)" })), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 16, fontWeight: 700, color: "var(--cream)" } }, "\u041D\u0438\u0447\u0435\u0433\u043E \u043D\u0435 \u043D\u0430\u0448\u043B\u0438"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13.5, marginTop: 6 } }, "\u041F\u043E\u043F\u0440\u043E\u0431\u0443\u0439 \u0434\u0440\u0443\u0433\u043E\u0435 \u0441\u043B\u043E\u0432\u043E \u2014 \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440, \xAB\u0441\u0442\u0430\u043A\u0430\u043D\xBB \u0438\u043B\u0438 \xAB\u043C\u043E\u043B\u043E\u043A\u043E\xBB.")), results.length > 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: "6px 16px 24px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12.5, color: "var(--cream-mute)", padding: "6px 2px 10px" } }, "\u041D\u0430\u0439\u0434\u0435\u043D\u043E ", results.length), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 9 } }, results.map((it) => /* @__PURE__ */ React.createElement("button", { key: it.part + it.n, onClick: () => onOpen(it), className: "row-tap card", style: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    padding: 9,
    cursor: "pointer",
    textAlign: "left"
  } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/warehouse/" + it.img, alt: "", loading: "lazy", style: { width: 54, height: 54, objectFit: "cover", borderRadius: 11, background: "#fff", flex: "0 0 auto" } }), /* @__PURE__ */ React.createElement("div", { style: { flex: 1, minWidth: 0 } }, /* @__PURE__ */ React.createElement("div", { style: {
    fontSize: 14,
    fontWeight: 600,
    color: "var(--cream)",
    lineHeight: 1.3,
    display: "-webkit-box",
    WebkitLineClamp: 2,
    WebkitBoxOrient: "vertical",
    overflow: "hidden"
  } }, it.title), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 7, marginTop: 5 } }, /* @__PURE__ */ React.createElement(RecBadge, { rec: it.rec, withIcon: false }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11.5, color: "var(--cream-mute)" } }, it.partName))), /* @__PURE__ */ React.createElement(Icon, { name: "chevron-right", size: 18, color: "var(--cream-mute)" })))))));
}
window.Search = Search;
// ---- app.jsx ----
function App() {
  const [items, setItems] = React.useState(null);
  const [tab, setTab] = React.useState(() => {
    const t = localStorage.getItem("wh_tab");
    return t && t !== "quiz" ? t : "home";
  });
  const [part, setPart] = React.useState("posuda");
  const [sheet, setSheet] = React.useState(null);
  const isDesktop = window.useIsDesktop();
  React.useEffect(() => {
    window.WH.load().then(setItems).catch((e) => {
      console.error(e);
      setItems([]);
    });
  }, []);
  React.useEffect(() => {
    localStorage.setItem("wh_tab", tab);
  }, [tab]);
  const goTab = (t) => {
    setSheet(null);
    setTab(t);
  };
  const openPart = (p) => {
    setPart(p);
    setSheet(null);
    setTab("catalog");
  };
  if (!items) {
    return /* @__PURE__ */ React.createElement("div", { style: { flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, color: "var(--cream-mute)" } }, /* @__PURE__ */ React.createElement("img", { src: "./assets/logos/yahya-logo-gold.png", alt: "YAHYA", style: { height: 30, opacity: 0.9 } }), /* @__PURE__ */ React.createElement("div", { style: { width: 26, height: 26, border: "3px solid var(--choc-600)", borderTopColor: "var(--gold)", borderRadius: 999, animation: "spin 0.8s linear infinite" } }), /* @__PURE__ */ React.createElement("style", null, "@keyframes spin{to{transform:rotate(360deg)}}"));
  }
  const showNav = tab === "home" || tab === "catalog" || tab === "search";
  if (isDesktop) {
    return /* @__PURE__ */ React.createElement("div", { style: { height: "100%", display: "flex", minHeight: 0, position: "relative" } }, /* @__PURE__ */ React.createElement(Sidebar, { tab, onTab: goTab }), /* @__PURE__ */ React.createElement("main", { style: { flex: 1, minWidth: 0, display: "flex", flexDirection: "column", minHeight: 0 } }, tab === "home" && /* @__PURE__ */ React.createElement("div", { className: "scroll" }, /* @__PURE__ */ React.createElement(Home, { items, wide: true, onTab: goTab, onPart: openPart, onSearch: () => goTab("search") })), tab === "guide" && /* @__PURE__ */ React.createElement(Guide, { wide: true, onTab: goTab, onPart: openPart }), tab === "catalog" && /* @__PURE__ */ React.createElement(Catalog, { items, wide: true, initialPart: part, onOpen: setSheet, onTab: goTab }), tab === "search" && /* @__PURE__ */ React.createElement(Search, { items, wide: true, onOpen: setSheet, onTab: goTab })), sheet && /* @__PURE__ */ React.createElement(ProductSheet, { it: sheet, desktop: true, onClose: () => setSheet(null) }));
  }
  return /* @__PURE__ */ React.createElement("div", { style: { height: "100%", display: "flex", flexDirection: "column", position: "relative", minHeight: 0 } }, tab === "home" && /* @__PURE__ */ React.createElement("div", { className: "scroll" }, /* @__PURE__ */ React.createElement(Home, { items, onTab: goTab, onPart: openPart, onSearch: () => goTab("search") })), tab === "guide" && /* @__PURE__ */ React.createElement(Guide, { onTab: goTab, onPart: openPart }), tab === "catalog" && /* @__PURE__ */ React.createElement(Catalog, { items, initialPart: part, onOpen: setSheet, onTab: goTab }), tab === "search" && /* @__PURE__ */ React.createElement(Search, { items, onOpen: setSheet, onTab: goTab }), showNav && /* @__PURE__ */ React.createElement(BottomNav, { tab, onTab: goTab }), sheet && /* @__PURE__ */ React.createElement(ProductSheet, { it: sheet, onClose: () => setSheet(null) }));
}
ReactDOM.createRoot(document.getElementById("root")).render(/* @__PURE__ */ React.createElement(App, null));
