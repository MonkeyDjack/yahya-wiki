// Catalog: parts tabs, subcategory filter, product grid.
function Catalog({ items, initialPart, onOpen, onTab, wide }) {
  const [part, setPart] = React.useState(initialPart || "posuda");
  const [rec, setRec] = React.useState("all");
  const [section, setSection] = React.useState("all");

  React.useEffect(() => { if (initialPart) setPart(initialPart); }, [initialPart]);
  React.useEffect(() => { setSection("all"); setRec("all"); }, [part]);

  const partItems = items.filter((it) => it.part === part);
  const sections = [...new Set(partItems.map((it) => it.section).filter(Boolean))];
  const hasSections = sections.length > 1 || (sections.length === 1 && sections[0] !== "");

  let shown = partItems;
  if (rec !== "all") shown = shown.filter((it) => it.rec.key === rec || (rec !== "oba" && it.rec.key === "oba"));
  if (section !== "all") shown = shown.filter((it) => it.section === section);

  const groups = section === "all" && hasSections
    ? window.WH.groupBySection(shown)
    : [["", shown]];

  const recFilters = [["all", "Все"], ["bar", "Бар"], ["mag", "Магазин"], ["oba", "Оба"]];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <TopBar title="Что есть на складе"
        onBack={wide ? undefined : () => onTab("home")}
        right={<button onClick={() => onTab("search")} aria-label="Поиск" style={{ background: "var(--choc-700)", border: "1px solid var(--line)", color: "var(--cream)", width: 38, height: 38, borderRadius: 11, display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer" }}><Icon name="search" size={19} /></button>} />

      {/* part chips */}
      <div style={{ display: "flex", gap: 8, flexWrap: wide ? "wrap" : "nowrap", overflowX: wide ? "visible" : "auto", padding: "12px 16px 10px", borderBottom: "1px solid var(--line)" }}>
        {window.WH.PARTS.map((p) => (
          <Chip key={p.key} active={part === p.key} icon={p.icon} onClick={() => setPart(p.key)}>{p.chip}</Chip>
        ))}
      </div>

      <div className="scroll">
        {/* count */}
        <div style={{ padding: "14px 16px 6px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: 13, color: "var(--cream-mute)" }}>Найдено <b style={{ color: "var(--cream)" }}>{shown.length}</b> поз.</span>
            <span style={{ fontSize: 12, color: "var(--cream-mute)" }}>{window.WH.partOf(part).name}</span>
          </div>
        </div>

        {/* grid grouped */}
        <div style={{ padding: "8px 16px 24px" }}>
          {groups.map(([sec, list]) => (
            <div key={sec || "_"}>
              {sec && (
                <div style={{ display: "flex", alignItems: "center", gap: 9, margin: "16px 2px 11px" }}>
                  <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "var(--gold)" }}>{sec}</span>
                  <span style={{ height: 1, flex: 1, background: "var(--line)" }} />
                  <span style={{ fontSize: 12, color: "var(--cream-mute)" }}>{list.length}</span>
                </div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: wide ? "repeat(auto-fill, minmax(190px, 1fr))" : "1fr 1fr", gap: wide ? 16 : 12 }}>
                {list.map((it) => <Tile key={it.part + it.n} it={it} onOpen={onOpen} />)}
              </div>
            </div>
          ))}
          {shown.length === 0 && (
            <div style={{ textAlign: "center", color: "var(--cream-mute)", padding: "40px 0", fontSize: 14 }}>Ничего не найдено в этом фильтре.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function Tile({ it, onOpen }) {
  return (
    <button onClick={() => onOpen(it)} className="row-tap card" style={{
      padding: 0, overflow: "hidden", cursor: "pointer", textAlign: "left", display: "flex", flexDirection: "column",
    }}>
      <div style={{ aspectRatio: "1/1", background: "#fff", position: "relative" }}>
        <img src={"./assets/warehouse/" + it.img} alt="" loading="lazy"
          style={{ width: "100%", height: "100%", objectFit: "cover" }} />
        <span style={{ position: "absolute", top: 8, left: 8 }}><RecBadge rec={it.rec} withIcon={false} /></span>
        {it.flag === "add" && <span style={{ position: "absolute", top: 8, right: 8, width: 22, height: 22, borderRadius: 999, background: "rgba(224,138,106,0.92)", color: "#2a1a10", display: "inline-flex", alignItems: "center", justifyContent: "center" }} title="Нет в базе — добавить"><Icon name="plus" size={13} strokeWidth={3} /></span>}
      </div>
      <div style={{ padding: "10px 11px 12px", flex: 1, display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--cream)", lineHeight: 1.3,
          display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{it.title}</span>
        <span style={{ fontSize: 11, color: "var(--cream-mute)", marginTop: "auto" }}>{it.unitLabel}{it.pack ? " · " + it.pack.unitPack : ""}</span>
      </div>
    </button>
  );
}

window.Catalog = Catalog;
