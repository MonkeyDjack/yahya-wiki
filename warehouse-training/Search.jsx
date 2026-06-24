// Global search by name / draft name / code.
function Search({ items, onOpen, onTab, wide }) {
  const [q, setQ] = React.useState("");
  const inputRef = React.useRef(null);
  React.useEffect(() => { if (inputRef.current) inputRef.current.focus(); }, []);

  const query = q.trim().toLowerCase();
  const results = query.length === 0 ? [] : items.filter((it) => {
    const hay = (it.title + " " + it.draft + " " + it.section + " " + it.code + " " + it.partName).toLowerCase();
    return query.split(/\s+/).every((w) => hay.includes(w));
  }).slice(0, 60);

  const suggestions = ["стакан", "молоко", "сироп", "тарелка", "крышка", "пакет"];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <TopBar title="Поиск по складу" onBack={() => onTab("home")} />

      <div style={{ padding: "14px 16px 8px", maxWidth: wide ? 760 : "none", margin: wide ? "0 auto" : "0", width: "100%", boxSizing: "border-box" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, background: "var(--choc-800)",
          border: "1px solid var(--line-strong)", borderRadius: 14, padding: "12px 14px" }}>
          <Icon name="search" size={19} color="var(--gold)" />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или код…"
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "var(--cream)",
              fontFamily: "var(--font-sans)", fontSize: 15.5 }} />
          {q && <button onClick={() => setQ("")} aria-label="Очистить" style={{ background: "none", border: "none", color: "var(--cream-mute)", cursor: "pointer", display: "inline-flex" }}><Icon name="x" size={18} /></button>}
        </div>
      </div>

      <div className="scroll" style={wide ? { maxWidth: 760, margin: "0 auto", width: "100%" } : null}>
        {query.length === 0 && (
          <div style={{ padding: "10px 18px" }}>
            <div style={{ fontSize: 12, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 12 }}>Популярное</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {suggestions.map((s) => <Chip key={s} onClick={() => setQ(s)}>{s}</Chip>)}
            </div>
          </div>
        )}

        {query.length > 0 && results.length === 0 && (
          <div style={{ textAlign: "center", padding: "56px 30px 0", color: "var(--cream-mute)" }}>
            <div style={{ width: 70, height: 70, borderRadius: 999, margin: "0 auto 16px", background: "var(--choc-700)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Icon name="search-x" size={34} color="var(--cream-mute)" />
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "var(--cream)" }}>Ничего не нашли</div>
            <div style={{ fontSize: 13.5, marginTop: 6 }}>Попробуй другое слово — например, «стакан» или «молоко».</div>
          </div>
        )}

        {results.length > 0 && (
          <div style={{ padding: "6px 16px 24px" }}>
            <div style={{ fontSize: 12.5, color: "var(--cream-mute)", padding: "6px 2px 10px" }}>Найдено {results.length}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {results.map((it) => (
                <button key={it.part + it.n} onClick={() => onOpen(it)} className="row-tap card" style={{
                  display: "flex", alignItems: "center", gap: 12, padding: 9, cursor: "pointer", textAlign: "left" }}>
                  <img src={"./assets/warehouse/" + it.img} alt="" loading="lazy" style={{ width: 54, height: 54, objectFit: "cover", borderRadius: 11, background: "#fff", flex: "0 0 auto" }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: "var(--cream)", lineHeight: 1.3,
                      display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{it.title}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 5 }}>
                      <RecBadge rec={it.rec} withIcon={false} />
                      <span style={{ fontSize: 11.5, color: "var(--cream-mute)" }}>{it.partName}</span>
                    </div>
                  </div>
                  <Icon name="chevron-right" size={18} color="var(--cream-mute)" />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

window.Search = Search;
