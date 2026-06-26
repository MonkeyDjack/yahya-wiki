// Step-by-step guide: how to create a warehouse request in 1С.
// Each step shows a real 1С screenshot (assets/warehouse/guide/step-N.png)
// in a unified frame with tap-to-zoom, plus concrete text and warnings.
function Guide({ onTab, onPart, wide }) {
  const [step, setStep] = React.useState(0);
  const [zoom, setZoom] = React.useState(null); // полноэкранный просмотр скрина
  const scrollRef = React.useRef(null);

  const steps = [
    {
      img: "step-1.png", title: "Открой «Заявку на перемещение»",
      body: "В 1С вверху выбери раздел «Склад». В «Схеме работы» нажми «Заявка на перемещение».",
      tip: { kind: "warn", text: "Не перепутай: нужна именно «Заявка на перемещение», а не «Перемещение товаров» или «Движение МБП»." },
    },
    {
      img: "step-2.png", title: "Создай новый документ",
      body: "Откроется список заявок. Нажми зелёный «+» (Добавить) в панели сверху — создастся новая пустая заявка.",
    },
    {
      img: "step-3.png", title: "Заполни «Отправитель» и «Получатель»",
      body: "В шапке заявки два главных поля. Организация уже заполнена. Нажми «…» в поле «Отправитель» (откуда берём товар), затем в «Получатель» (куда придёт).",
      tip: { kind: "info", text: "Столбцы «Цена» и «Сумма» заполнять не нужно." },
    },
    {
      img: "step-4.png", title: "Отправитель — склад Ибраимова",
      body: "В окне «Склады» открой папку «Ибраимова 249» и выбери склад, где лежит нужный товар:",
      list: [
        ["Эмиль … МБП", "посуда, оборудование"],
        ["Эмиль … прочее", "хоз. товары"],
        ["Эмиль … Сырьё", "молоко, сиропы, соки, чай"],
        ["Эмиль … Упаковка", "стаканы, крышки, пакеты, коробки"],
      ],
    },
    {
      img: "step-5.png", title: "Получатель — твой филиал",
      body: "Открой папку своего филиала (например «Склад Азия молл») и выбери, куда придёт товар:",
      hint2: true,
    },
    {
      img: "step-6.png", title: "Добавь товар — выбери тип данных",
      body: "Добавь строку в таблицу. 1С спросит «Выбор типа данных». Тип зависит от позиции и указан в её карточке в каталоге:",
      regHint: true,
      cta: { label: "Открыть каталог", to: "catalog" },
      tip: { kind: "info", text: "Бери точное название из карточки (кнопка «Скопировать название») — найдёшь позицию без ошибок." },
    },
    {
      img: "step-7.png", title: "Количество, проверка, ОК",
      body: "Впиши «Количество» числом. В «Комментарий» — единицу или фасовку по позиции: шт, кг, л, «1 рукав», «1 пачка» (смотри карточку товара). Сверь Отправителя/Получателя и нажми «ОК» / «Записать».",
      example: true,
      done: true,
    },
  ];

  const s = steps[step];
  const last = step === steps.length - 1;
  const go = (d) => {
    setStep((x) => Math.min(steps.length - 1, Math.max(0, x + d)));
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };
  const imgSrc = "./assets/warehouse/guide/" + s.img;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <TopBar title="Как создать заявку" subtitle={"Шаг " + (step + 1) + " из " + steps.length}
        onBack={step > 0 ? () => go(-1) : () => onTab("home")} />

      {/* progress */}
      <div style={{ display: "flex", gap: 5, padding: "12px 18px 4px", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0", width: "100%", boxSizing: "border-box" }}>
        {steps.map((_, i) => (
          <div key={i} style={{ flex: 1, height: 5, borderRadius: 999,
            background: i <= step ? "var(--gold)" : "var(--choc-600)", transition: "background .25s ease" }} />
        ))}
      </div>

      <div ref={scrollRef} className="scroll" style={{ paddingBottom: 16 }}>
        <div key={step} className="fade-in" style={{ padding: "16px 20px 0", maxWidth: wide ? 680 : "none", margin: wide ? "0 auto" : "0" }}>
          {/* real 1С screenshot — unified frame, tap to zoom */}
          <button onClick={() => setZoom(imgSrc)} aria-label="Увеличить скриншот" style={{
            display: "block", width: "100%", padding: 8, marginBottom: 18, cursor: "zoom-in",
            background: "var(--choc-900)", border: "1px solid var(--line-strong)", borderRadius: 18, position: "relative",
          }}>
            <img src={imgSrc} alt={"Шаг " + (step + 1)} style={{
              display: "block", width: "100%", maxHeight: wide ? 380 : "44vh",
              objectFit: "contain", borderRadius: 11, background: "#1d1109",
            }} />
            <span style={{ position: "absolute", left: 14, top: 14, fontSize: 12, fontWeight: 800,
              color: "var(--choc-900)", background: "var(--gold)", borderRadius: 8, padding: "3px 9px" }}>Шаг {step + 1}</span>
            <span style={{ position: "absolute", right: 14, bottom: 14, display: "inline-flex", alignItems: "center", gap: 6,
              fontSize: 11.5, fontWeight: 600, color: "var(--cream-dim)", background: "rgba(28,16,8,0.82)",
              border: "1px solid var(--line)", borderRadius: 999, padding: "5px 10px" }}>
              <Icon name="expand" size={13} color="var(--gold)" />увеличить
            </span>
          </button>

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
                <div className="badge bar" style={{ marginBottom: 8 }}><Icon name="coffee" size={12} />Бар ЦУМ</div>
                <div style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>Если товар для бар-зоны</div>
              </div>
              <div style={{ background: "var(--mag-bg)", border: "1px solid rgba(169,193,120,0.35)", borderRadius: 14, padding: 14 }}>
                <div className="badge mag" style={{ marginBottom: 8 }}><Icon name="store" size={12} />Магазин ЦУМ</div>
                <div style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>Если товар для магазина</div>
              </div>
            </div>
          )}

          {/* Номенклатура vs Товары — выбор типа данных */}
          {s.regHint && (
            <div style={{ display: "grid", gap: 10, marginTop: 18 }}>
              <div style={{ background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: 14, display: "flex", gap: 12, alignItems: "center" }}>
                <span className="badge oba"><Icon name="list-tree" size={12} />Номенклатура</span>
                <span style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>большинство позиций склада</span>
              </div>
              <div style={{ background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: 14, display: "flex", gap: 12, alignItems: "center" }}>
                <span className="badge mag"><Icon name="package" size={12} />Товары</span>
                <span style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.4 }}>часть упаковки и розничных позиций</span>
              </div>
              <div style={{ fontSize: 12.5, color: "var(--cream-mute)", lineHeight: 1.45, padding: "0 2px" }}>
                Точный тип для каждой позиции написан в её карточке в каталоге.
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
                  <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" }}>Количество</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "var(--cream)", marginTop: 3 }}>1</div>
                </div>
                <div style={{ padding: "12px 14px" }}>
                  <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".08em", textTransform: "uppercase" }}>Комментарий</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "var(--gold)", marginTop: 3 }}>1 рукав (27 шт)</div>
                </div>
              </div>
            </div>
          )}

          {/* info / warning tip */}
          {s.tip && (
            <div style={{ marginTop: 18, display: "flex", gap: 10,
              background: s.tip.kind === "warn" ? "rgba(224,138,106,0.12)" : "rgba(210,168,98,0.1)",
              border: "1px solid " + (s.tip.kind === "warn" ? "rgba(224,138,106,0.34)" : "rgba(210,168,98,0.28)"),
              borderRadius: 13, padding: "12px 14px" }}>
              <Icon name={s.tip.kind === "warn" ? "alert-triangle" : "info"} size={18}
                color={s.tip.kind === "warn" ? "var(--add)" : "var(--gold)"} style={{ marginTop: 1, flex: "0 0 auto" }} />
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

      {/* fullscreen screenshot zoom: на телефоне можно прокрутить/панорамировать крупный скрин */}
      {zoom && (
        <div onClick={() => setZoom(null)} style={{
          position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.92)",
          overflow: "auto", display: "flex", alignItems: "flex-start", justifyContent: "center", padding: 12,
        }}>
          <img src={zoom} alt="" onClick={(e) => e.stopPropagation()} style={{
            display: "block", minWidth: "100%", width: "auto", height: "auto", maxWidth: "none", margin: "auto", borderRadius: 8,
          }} />
          <button onClick={() => setZoom(null)} aria-label="Закрыть" style={{
            position: "fixed", right: 14, top: 14, width: 40, height: 40, borderRadius: 12,
            background: "rgba(28,16,8,0.9)", border: "1px solid var(--line-strong)", color: "var(--cream)",
            cursor: "pointer", display: "inline-flex", alignItems: "center", justifyContent: "center", zIndex: 201,
          }}><Icon name="x" size={20} /></button>
        </div>
      )}
    </div>
  );
}

window.Guide = Guide;
