// App orchestrator: loads catalog, routes screens, holds the product sheet.
function App() {
  const [items, setItems] = React.useState(null);
  const [tab, setTab] = React.useState(() => {
    const t = localStorage.getItem("wh_tab");
    return t && t !== "quiz" ? t : "home";
  });
  const [part, setPart] = React.useState("posuda");
  const [sheet, setSheet] = React.useState(null);
  const isDesktop = window.useIsDesktop();

  React.useEffect(() => { window.WH.load().then(setItems).catch((e) => { console.error(e); setItems([]); }); }, []);
  React.useEffect(() => { localStorage.setItem("wh_tab", tab); }, [tab]);

  const goTab = (t) => { setSheet(null); setTab(t); };
  const openPart = (p) => { setPart(p); setSheet(null); setTab("catalog"); };

  if (!items) {
    return (
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, color: "var(--cream-mute)" }}>
        <img src="./assets/logos/yahya-logo-gold.png" alt="YAHYA" style={{ height: 30, opacity: 0.9 }} />
        <div style={{ width: 26, height: 26, border: "3px solid var(--choc-600)", borderTopColor: "var(--gold)", borderRadius: 999, animation: "spin 0.8s linear infinite" }} />
        <style>{"@keyframes spin{to{transform:rotate(360deg)}}"}</style>
      </div>
    );
  }

  const showNav = tab === "home" || tab === "catalog" || tab === "search";

  if (isDesktop) {
    return (
      <div style={{ height: "100%", display: "flex", minHeight: 0, position: "relative" }}>
        <Sidebar tab={tab} onTab={goTab} />
        <main style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
          {tab === "home" && (
            <div className="scroll">
              <Home items={items} wide onTab={goTab} onPart={openPart} onSearch={() => goTab("search")} />
            </div>
          )}
          {tab === "guide" && <Guide wide onTab={goTab} onPart={openPart} />}
          {tab === "catalog" && <Catalog items={items} wide initialPart={part} onOpen={setSheet} onTab={goTab} />}
          {tab === "search" && <Search items={items} wide onOpen={setSheet} onTab={goTab} />}
        </main>
        {sheet && <ProductSheet it={sheet} desktop onClose={() => setSheet(null)} />}
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", position: "relative", minHeight: 0 }}>
      {tab === "home" && (
        <div className="scroll">
          <Home items={items} onTab={goTab} onPart={openPart} onSearch={() => goTab("search")} />
        </div>
      )}
      {tab === "guide" && <Guide onTab={goTab} onPart={openPart} />}
      {tab === "catalog" && <Catalog items={items} initialPart={part} onOpen={setSheet} onTab={goTab} />}
      {tab === "search" && <Search items={items} onOpen={setSheet} onTab={goTab} />}

      {showNav && <BottomNav tab={tab} onTab={goTab} />}
      {sheet && <ProductSheet it={sheet} onClose={() => setSheet(null)} />}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
