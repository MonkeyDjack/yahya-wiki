// Product sheet — the core "how to order" screen, slides up over the app.
function ProductSheet({ it, onClose, desktop }) {
  const [copied, setCopied] = React.useState(false);
  const mounted = React.useRef(false);
  const [show, setShow] = React.useState(false);
  React.useEffect(() => { const t = setTimeout(() => setShow(true), 10); return () => clearTimeout(t); }, []);

  if (!it) return null;
  const copy = () => {
    const text = it.title;
    const done = () => { setCopied(true); setTimeout(() => setCopied(false), 1600); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(done);
    else done();
  };
  const close = () => { setShow(false); setTimeout(onClose, 240); };

  const reg = window.WH.regInfo(it);
  const flagInfo = it.flag === "add"
    ? { c: "var(--add)", bg: "rgba(224,138,106,0.14)", icon: "plus-circle", t: "Нет в базе — нужно добавить" }
    : it.flag === "check"
    ? { c: "var(--warn)", bg: "rgba(224,177,90,0.14)", icon: "alert-triangle", t: "Уточнить вариант в базе" }
    : null;

  const panelStyle = desktop
    ? {
        position: "absolute", left: "50%", top: "50%", width: "min(480px, 92%)", maxHeight: "88%",
        background: "var(--choc-800)", borderRadius: 24,
        transform: show ? "translate(-50%, -50%) scale(1)" : "translate(-50%, -47%) scale(0.97)",
        opacity: show ? 1 : 0,
        transition: "transform .26s var(--ease-out), opacity .2s ease",
        display: "flex", flexDirection: "column", boxShadow: "0 26px 70px rgba(0,0,0,0.55)",
      }
    : {
        position: "absolute", left: 0, right: 0, bottom: 0, maxHeight: "94%",
        background: "var(--choc-800)", borderTopLeftRadius: 26, borderTopRightRadius: 26,
        transform: show ? "translateY(0)" : "translateY(100%)", transition: "transform .26s var(--ease-out)",
        display: "flex", flexDirection: "column", boxShadow: "0 -16px 50px rgba(0,0,0,0.5)",
      };

  return (
    // fixed (не absolute): прикрепляет лист к окну/iframe, а не к концу прокрутки.
    // У телефонной раскладки #app только min-height:100vh без definite height, поэтому
    // цепочка height:100% не резолвится и absolute-оверлей растягивался на всю высоту
    // контента — лист уезжал в самый низ. fixed считается от вьюпорта iframe.
    <div style={{ position: "fixed", inset: 0, zIndex: 60 }}>
      <div onClick={close} style={{ position: "absolute", inset: 0, background: "rgba(15,8,3,0.6)",
        opacity: show ? 1 : 0, transition: "opacity .24s ease" }} />
      <div style={panelStyle}>
        {/* grab + close */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "10px 0 4px", position: "relative" }}>
          {!desktop && <span style={{ width: 40, height: 4, borderRadius: 999, background: "var(--line-strong)" }} />}
          <button onClick={close} aria-label="Закрыть" style={{ position: "absolute", right: 14, top: 8,
            width: 34, height: 34, borderRadius: 10, background: "var(--choc-600)", border: "none",
            color: "var(--cream)", cursor: "pointer", display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
            <Icon name="x" size={18} />
          </button>
        </div>

        <div className="scroll" style={{ paddingBottom: 20 }}>
          {/* photo */}
          <div style={{ margin: "8px 16px 0", borderRadius: 18, overflow: "hidden", background: "#fff", aspectRatio: "4/3" }}>
            <img src={"./assets/warehouse/" + it.img} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
          </div>

          <div style={{ padding: "16px 18px 0" }}>
            <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
              <RecBadge rec={it.rec} />
              <RegBadge reg={reg} />
              <span className="badge oba"><Icon name="warehouse" size={12} />{it.sklad}</span>
            </div>

            {/* exact name — the key field */}
            <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 6 }}>Точное название в базе 1С</div>
            <div style={{ background: "var(--choc-700)", border: "1px solid var(--line-strong)", borderRadius: 14, padding: "14px 15px" }}>
              <div style={{ fontSize: 17, fontWeight: 700, color: "var(--cream)", lineHeight: 1.35 }}>{it.title}</div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 }}>
                <span style={{ fontSize: 12, color: "var(--cream-mute)" }}>{it.code ? "код …" + it.code : "код уточняется"}{it.draft && it.draft !== it.title ? " · «" + it.draft + "»" : ""}</span>
              </div>
              <button onClick={copy} style={{ marginTop: 12, width: "100%", display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8,
                background: copied ? "rgba(159,192,106,0.18)" : "var(--gold)", color: copied ? "var(--ok)" : "var(--choc-900)",
                border: "none", borderRadius: 11, padding: "12px", fontWeight: 700, fontSize: 13, letterSpacing: ".06em",
                textTransform: "uppercase", cursor: "pointer", transition: "background .2s ease" }}>
                <Icon name={copied ? "check" : "copy"} size={16} />{copied ? "Скопировано" : "Скопировать название"}
              </button>
            </div>

            {flagInfo && (
              <div style={{ marginTop: 12, display: "flex", gap: 9, background: flagInfo.bg, borderRadius: 12, padding: "11px 13px" }}>
                <Icon name={flagInfo.icon} size={17} color={flagInfo.c} />
                <span style={{ fontSize: 13, color: "var(--cream-dim)" }}>{flagInfo.t}</span>
              </div>
            )}

            {/* description / note (напр. список вкусов сиропов) */}
            {it.note && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 11, color: "var(--cream-mute)", letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 6 }}>Описание</div>
                <p style={{ fontSize: 13.5, color: "var(--cream-dim)", lineHeight: 1.5, margin: 0 }}>{it.note}</p>
              </div>
            )}

            {/* How to order */}
            <div style={{ marginTop: 20, fontSize: 13, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "var(--gold)", marginBottom: 10 }}>Как заказывать</div>
            <div style={{ display: "grid", gap: 9 }}>
              <FieldRow icon="ruler" label="Единица измерения" value={it.unitLabel} />
              {it.pack ? (
                <React.Fragment>
                  <FieldRow icon="boxes" label="Фасовка" value={it.pack.unitPack + " = " + it.pack.per + " шт"} />
                  <FieldRow icon="pencil" label="В заявке писать" value={"«" + it.pack.write + "»"} accent />
                </React.Fragment>
              ) : (
                <React.Fragment>
                  <FieldRow icon="hash" label="Заказ" value="Штучно" />
                  <FieldRow icon="pencil" label="В заявке писать" value="Количество, напр. «5»" />
                </React.Fragment>
              )}
            </div>

            {it.pack && (
              <div style={{ marginTop: 12, display: "flex", gap: 9, background: "rgba(210,168,98,0.1)", border: "1px solid rgba(210,168,98,0.26)", borderRadius: 12, padding: "11px 13px" }}>
                <Icon name="info" size={17} color="var(--gold)" />
                <span style={{ fontSize: 13, color: "var(--cream-dim)", lineHeight: 1.45 }}>{it.pack.hint}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function FieldRow({ icon, label, value, accent }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, background: "var(--choc-700)", border: "1px solid var(--line)", borderRadius: 13, padding: "13px 14px" }}>
      <span style={{ width: 34, height: 34, borderRadius: 9, background: "rgba(210,168,98,0.13)", color: "var(--gold)", display: "inline-flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>
        <Icon name={icon} size={17} />
      </span>
      <span style={{ fontSize: 12.5, color: "var(--cream-mute)", flex: 1 }}>{label}</span>
      <span style={{ fontSize: 14.5, fontWeight: 700, color: accent ? "var(--gold)" : "var(--cream)", textAlign: "right" }}>{value}</span>
    </div>
  );
}

window.ProductSheet = ProductSheet;
