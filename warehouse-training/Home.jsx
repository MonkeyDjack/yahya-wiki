// Home dashboard.
function Home({ items, onTab, onPart, onSearch, wide }) {
  const counts = {};
  items.forEach((it) => { counts[it.part] = (counts[it.part] || 0) + 1; });
  const tileColor = {
    posuda: ["#caa86a", "rgba(202,168,106,0.14)"],
    hoz: ["#a9c178", "rgba(169,193,120,0.14)"],
    syrye: ["#e0b08a", "rgba(224,176,138,0.14)"],
    upakovka: ["#cf9f6a", "rgba(207,159,106,0.14)"],
    oborud: ["#bdb0a0", "rgba(189,176,160,0.14)"],
  };

  return (
    <div className="fade-in" style={wide ? { maxWidth: 1060, margin: "0 auto", padding: "14px 10px 0" } : null}>
      {/* hero */}
      <div style={{ padding: "26px 20px 18px", borderRadius: wide ? 22 : 0, background: "linear-gradient(180deg, #36230f, var(--app-bg))" }}>
        <img src="./assets/logos/yahya-logo-gold.png" alt="YAHYA" style={{ height: 34, display: "block", marginBottom: 22 }} />
        <div className="eyebrow" style={{ marginBottom: 10 }}>Склад Ибраимова · ХОЗ</div>
        <h1 className="h-screen" style={{ fontSize: wide ? 34 : 27, lineHeight: 1.12 }}>Заявки на склад ХОЗ</h1>
        <p style={{ color: "var(--cream-dim)", fontSize: 14.5, margin: "12px 0 0", maxWidth: 320 }}>
          Научись заказывать правильно за 5 минут — что есть на складе и как это заказывать.
        </p>

        {/* search */}
        <button onClick={onSearch} style={{
          marginTop: 18, width: "100%", display: "flex", alignItems: "center", gap: 11,
          background: "var(--choc-800)", border: "1px solid var(--line-strong)", borderRadius: 14,
          padding: "13px 15px", cursor: "pointer", color: "var(--cream-mute)", fontSize: 14.5,
          fontFamily: "var(--font-sans)",
        }}>
          <Icon name="search" size={19} color="var(--gold)" />
          Поиск по складу…
        </button>
      </div>

      {/* two big entries */}
      <div style={{ padding: "6px 20px 0", display: "grid", gap: 12, gridTemplateColumns: wide ? "1fr 1fr" : "1fr" }}>
        <BigEntry icon="list-checks" title="Как создать заявку"
          desc="Пошаговый гайд в 1С — 6 простых шагов" tone="gold"
          onClick={() => onTab("guide")} />
        <BigEntry icon="boxes" title="Что есть на складе"
          desc={items.length + " позиций с фото и правилами заказа"} tone="plain"
          onClick={() => onTab("catalog")} />
      </div>

      {/* part tiles */}
      <div style={{ padding: "22px 20px 8px" }}>
        <div className="eyebrow" style={{ marginBottom: 12 }}>Части склада</div>
        <div style={{ display: "grid", gridTemplateColumns: wide ? "repeat(3, 1fr)" : "1fr 1fr", gap: 11 }}>
          {window.WH.PARTS.map((p, i) => {
            const [fg, bg] = tileColor[p.key];
            const full = !wide && p.key === "oborud";
            return (
              <button key={p.key} onClick={() => onPart(p.key)} className="row-tap" style={{
                gridColumn: full ? "1 / -1" : "auto",
                display: "flex", alignItems: "center", gap: 12, textAlign: "left",
                background: "var(--choc-700)", border: "1px solid var(--line)", borderRadius: 16,
                padding: "14px 14px", cursor: "pointer",
              }}>
                <span style={{ width: 42, height: 42, borderRadius: 12, background: bg, color: fg,
                  display: "inline-flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>
                  <Icon name={p.icon} size={22} />
                </span>
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: "block", fontSize: 14.5, fontWeight: 700, color: "var(--cream)" }}>{p.chip}</span>
                  <span style={{ display: "block", fontSize: 12, color: "var(--cream-mute)" }}>{p.name} · {counts[p.key] || 0} поз.</span>
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <div style={{ height: 16 }} />
    </div>
  );
}

function BigEntry({ icon, title, desc, tone, onClick }) {
  const gold = tone === "gold";
  return (
    <button onClick={onClick} className="row-tap" style={{
      display: "flex", alignItems: "center", gap: 15, textAlign: "left", cursor: "pointer",
      background: gold ? "linear-gradient(105deg, #d2a862, #b98e48)" : "var(--choc-700)",
      border: gold ? "none" : "1px solid var(--line-strong)", borderRadius: 18, padding: "18px 18px",
    }}>
      <span style={{ width: 52, height: 52, borderRadius: 14, flex: "0 0 auto",
        background: gold ? "rgba(34,20,9,0.16)" : "rgba(210,168,98,0.14)",
        color: gold ? "var(--choc-900)" : "var(--gold)",
        display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
        <Icon name={icon} size={27} />
      </span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ display: "block", fontSize: 17, fontWeight: 800, letterSpacing: ".02em",
          textTransform: "uppercase", color: gold ? "var(--choc-900)" : "var(--cream)" }}>{title}</span>
        <span style={{ display: "block", fontSize: 13, marginTop: 3,
          color: gold ? "rgba(34,20,9,0.7)" : "var(--cream-mute)" }}>{desc}</span>
      </span>
      <Icon name="arrow-right" size={22} color={gold ? "var(--choc-900)" : "var(--gold)"} />
    </button>
  );
}

window.Home = Home;
