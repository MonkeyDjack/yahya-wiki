// YAHYA warehouse training — data layer. Loads catalog.json and exposes helpers.
window.WH = (function () {
  const PARTS = [
    { key: "posuda",   name: "Посуда",        chip: "Склад МБП",      short: "Посуда",      sklad: "Склад МБП",      icon: "utensils",   emoji: "🍽" },
    { key: "hoz",      name: "Хоз. товары",   chip: "Склад Прочее",   short: "Хоз.",        sklad: "Склад Прочее",   icon: "spray-can",  emoji: "🧽" },
    { key: "syrye",    name: "Сырьё",         chip: "Склад Сырьё",    short: "Сырьё",       sklad: "Склад Сырьё",    icon: "milk",       emoji: "🥛" },
    { key: "upakovka", name: "Упаковка",      chip: "Склад Упаковка", short: "Упаковка",    sklad: "Склад Упаковка", icon: "package",    emoji: "📦" },
    { key: "oborud",   name: "Оборудование",  chip: "Оборудование",   short: "Оборуд.",     sklad: "Склад МБП",      icon: "wrench",     emoji: "⚙️" },
  ];
  const partOf = (k) => PARTS.find((p) => p.key === k);

  // Receiver -> normalized {key,label}
  function receiver(it) {
    const r = (it.receiver || "").toLowerCase();
    const hasBar = r.includes("бар");
    const hasMag = r.includes("магаз");
    if (hasBar && hasMag) return { key: "oba", label: "Бар + Магазин" };
    if (hasBar) return { key: "bar", label: "Бар" };
    if (hasMag) return { key: "mag", label: "Магазин" };
    // fallback by part
    if (it.part === "syrye" || it.part === "upakovka") return { key: "bar", label: "Бар" };
    return { key: "mag", label: "Магазин" };
  }

  // A few known packaging facts (the DOCX "Фасовка" column is filled by Эмиль;
  // these are the canonical examples used in training).
  const PACK = {
    // paper cups & lids come in sleeves / boxes
    "стакан": { unitPack: "рукав", per: 27, write: "1 рукав", hint: "Бумажные стаканы идут рукавом по 27 шт." },
    "крышка": { unitPack: "рукав", per: 50, write: "1 рукав", hint: "Крышки идут рукавом." },
    "пакет":  { unitPack: "пачка", per: 100, write: "1 пачка", hint: "Пакеты — пачкой." },
  };
  function packaging(it) {
    const name = (it.exact || it.draft || "").toLowerCase();
    if (it.part === "upakovka" || it.part === "hoz") {
      for (const k in PACK) if (name.includes(k)) return PACK[k];
    }
    return null;
  }

  function enrich(raw) {
    return raw.map((it) => {
      const rec = receiver(it);
      const pack = packaging(it);
      return {
        ...it,
        title: (it.exact || it.draft || "").trim(),
        rec,
        pack,
        unitLabel: it.unit || "шт",
      };
    });
  }

  async function load() {
    const res = await fetch("catalog.json");
    const raw = await res.json();
    return enrich(raw);
  }

  function groupBySection(items) {
    const map = new Map();
    for (const it of items) {
      const s = it.section || "Все";
      if (!map.has(s)) map.set(s, []);
      map.get(s).push(it);
    }
    return [...map.entries()];
  }

  return { PARTS, partOf, receiver, packaging, load, groupBySection };
})();
