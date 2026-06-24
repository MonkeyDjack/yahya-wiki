// Step-by-step guide: how to create a warehouse request in 1С.
function Guide({ onTab, onPart, wide }) {
  const [step, setStep] = React.useState(0);
  const scrollRef = React.useRef(null);

  const steps = [
    {
      icon: "folder-plus", title: "Открой заявку в 1С",
      body: "В 1С зайди во вкладку СКЛАД → «Заявка на перемещение» и нажми «+», чтобы создать новую.",
      tip: { kind: "info", text: "Создавай отдельную заявку на каждый склад-отправитель." },
    },
    {
      icon: "warehouse", title: "Выбери отправителя",
      body: "Открой папку «Склад Ибраимова». Внутри 4 строки — выбери ту, где лежит нужный товар:",
      list: [
        ["Склад МБП", "посуда — чашки, стаканы, тарелки"],
        ["Склад Прочее", "хоз. товары — тряпки, пакеты, моющие"],
        ["Склад Сырьё", "молоко, сиропы, соки, чай"],
        ["Склад Упаковка", "стаканы, крышки, пакеты, коробки"],
      ],
    },
    {
      icon: "store", title: "Выбери получателя",
      body: "Открой папку своего филиала и выбери, куда придёт товар — БАР или МАГАЗИН.",
      hint2: true,
    },
    {
      icon: "search", title: "Добавь номенклатуру",
      body: "Ищи товар по точному названию из базы. Не угадывай — открой каталог и скопируй название, чтобы найти позицию без ошибок.",
      cta: { label: "Открыть каталог", to: "catalog" },
    },
    {
      icon: "boxes", title: "Укажи количество правильно",
      body: "Если товар заказывается упаковкой — пиши фасовку в комментарии. Если штучно — просто количество.",
      example: true,
    },
    {
      icon: "send", title: "Проверь и отправь",
      body: "Сверь отправителя, получателя и количество. Всё верно — жми «Провести и закрыть».",
      done: true,
    },
  ];

  const s = steps[step];
  const last = step === steps.length - 1;
  const go = (d) => {
    setStep((x) => Math.min(steps.length - 1, Math.max(0, x + d)));
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <TopBar title="Как создать заявку" subtitle={"Шаг " + (step + 1) + " из " + steps.length}
        onBack={step > 0 ? () => go(-1) : () => onTab("home")} />

      {/* progress */}
      <div style={{ display: "flex", gap: 5, padding: "12px 18px 4px", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0", width: "100%" }}>
        {steps.map((_, i) => (
          <div key={i} style={{ flex: 1, height: 5, borderRadius: 999,
            background: i <= step ? "var(--gold)" : "var(--choc-600)", transition: "background .25s ease" }} />
        ))}
      </div>

      <div ref={scrollRef} className="scroll" style={{ paddingBottom: 16 }}>
        <div key={step} className="fade-in" style={{ padding: "18px 20px 0", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0" }}>
          {/* big illustration */}
          <div style={{ height: 150, borderRadius: 20, marginBottom: 22,
            background: "radial-gradient(120% 120% at 30% 20%, #4a3322, #2f1e12)",
            border: "1px solid var(--line)", display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
            <span style={{ width: 88, height: 88, borderRadius: 24, background: "rgba(210,168,98,0.16)",
              color: "var(--gold)", display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
              <Icon name={s.icon} size={44} strokeWidth={1.8} />
            </span>
            <span style={{ position: "absolute", top: 14, right: 16, fontSize: 56, fontWeight: 900,
              color: "rgba(210,168,98,0.14)", lineHeight: 1 }}>{step + 1}</span>
          </div>

          <h2 className="h-screen" style={{ fontSize: 22 }}>{s.title}</h2>
          <p style={{ color: "var(--cream-dim)", fontSize: 15.5, lineHeight: 1.55, margin: "10px 0 0" }}>{s.body}</p>

          {/* senders list */}
          {s.list && (
            <div style={{ display: "grid", gap: 9, marginTop: 18 }}>
              {s.list.map(([h, d], i) => (
                <div key={i} className="card" style={{ padding: "13px 14px", display: "flex", gap: 11, alignItems: "center" }}>
                  <Icon name="folder" size={20} color="var(--gold)" />
                  <div>
                    <div style={{ fontSize: 14.5, fontWeight: 700, color: "var(--cream)" }}>{h}</div>
                    <div style={{ fontSize: 12.5, color: "var(--cream-mute)" }}>{d}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* bar vs magazin hint */}
          {s.hint2 && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 18 }}>
              <div style={{ background: "var(--bar-bg)", border: "1px solid rgba(216,166,87,0.35)", borderRadius: 14, padding: 14 }}>
                <div className="badge bar" style={{ marginBottom: 8 }}><Icon name="coffee" size={12} />Бар</div>
                <div style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>Сырьё, стаканы и крышки</div>
              </div>
              <div style={{ background: "var(--mag-bg)", border: "1px solid rgba(169,193,120,0.35)", borderRadius: 14, padding: 14 }}>
                <div className="badge mag" style={{ marginBottom: 8 }}><Icon name="store" size={12} />Магазин</div>
                <div style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>Посуда, коробки, хоз. товары</div>
              </div>
            </div>
          )}

          {/* packaging example */}
          {s.example && (
            <div className="card" style={{ marginTop: 18, padding: 0, overflow: "hidden" }}>
              <div style={{ display: "flex", gap: 13, padding: 14, alignItems: "center" }}>
                <img src="./assets/warehouse/upakovka-007.jpg" alt="" style={{ width: 64, height: 64, objectFit: "cover", borderRadius: 12, flex: "0 0 auto" }} />
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "var(--cream)", lineHeight: 1.3 }}>Стакан бумажный 350 мл</div>
                  <div className="badge bar" style={{ marginTop: 6 }}><Icon name="coffee" size={12} />Бар</div>
                </div>
              </div>
              <div style={{ borderTop: "1px solid var(--line)", display: "grid", gridTemplateColumns: "1fr 1fr" }}>
                <div style={{ padding: "12px 14px", borderRight: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" }}>Фасовка</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "var(--cream)", marginTop: 3 }}>рукав = 27 шт</div>
                </div>
                <div style={{ padding: "12px 14px" }}>
                  <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" }}>В заявке писать</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "var(--gold)", marginTop: 3 }}>«1 рукав»</div>
                </div>
              </div>
            </div>
          )}

          {/* generic info tip */}
          {s.tip && (
            <div style={{ marginTop: 18, display: "flex", gap: 10, background: "rgba(210,168,98,0.1)",
              border: "1px solid rgba(210,168,98,0.28)", borderRadius: 13, padding: "12px 14px" }}>
              <Icon name="info" size={18} color="var(--gold)" style={{ marginTop: 1 }} />
              <span style={{ fontSize: 13.5, color: "var(--cream-dim)", lineHeight: 1.45 }}>{s.tip.text}</span>
            </div>
          )}

          {/* inline cta */}
          {s.cta && (
            <button onClick={() => onTab(s.cta.to)} style={{
              marginTop: 16, width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
              background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 13,
              padding: "13px 15px", cursor: "pointer", color: "var(--cream)", fontSize: 14, fontWeight: 600,
            }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}><Icon name="boxes" size={18} color="var(--gold)" />{s.cta.label}</span>
              <Icon name="arrow-right" size={18} color="var(--gold)" />
            </button>
          )}

          {/* done */}
          {s.done && (
            <div style={{ marginTop: 18, textAlign: "center", padding: "10px 0 4px" }}>
              <div style={{ width: 64, height: 64, borderRadius: 999, margin: "0 auto 12px",
                background: "rgba(159,192,106,0.18)", color: "var(--ok)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon name="check" size={34} strokeWidth={3} />
              </div>
              <div style={{ fontSize: 17, fontWeight: 800, textTransform: "uppercase", letterSpacing: ".04em", color: "var(--cream)" }}>Готово!</div>
              <div style={{ fontSize: 13.5, color: "var(--cream-mute)", marginTop: 4 }}>Теперь ты умеешь создавать заявки.</div>
            </div>
          )}
        </div>
      </div>

      {/* footer nav */}
      <div style={{ padding: "12px 20px calc(14px + env(safe-area-inset-bottom))", borderTop: "1px solid var(--line)",
        display: "flex", gap: 10, background: "var(--choc-900)", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0", width: "100%", boxSizing: "border-box" }}>
        {step > 0 && <Btn variant="ghost" icon="chevron-left" onClick={() => go(-1)} style={{ flex: "0 0 auto", textTransform: "none", padding: "15px 16px" }}>Назад</Btn>}
        {!last && <Btn variant="primary" iconRight="chevron-right" full onClick={() => go(1)}>Дальше</Btn>}
        {last && (
          <Btn variant="primary" icon="boxes" full onClick={() => onTab("catalog")}>Перейти в каталог</Btn>
        )}
      </div>
    </div>
  );
}

window.Guide = Guide;
