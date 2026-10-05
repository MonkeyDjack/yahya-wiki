#!/bin/sh
# Сборка «Склада ХОЗ»: JSX → обычный JS, чтобы не тащить Babel (~3 МБ) в браузер.
# Запуск из папки warehouse-training:  sh build.sh   (нужен Node.js; esbuild скачается через npx)
# Править нужно *.jsx, затем пересобрать — app.bundle.js руками не редактировать.
set -e
cd "$(dirname "$0")"
OUT=app.bundle.js
echo "// СОБРАНО build.sh из *.jsx ($(date +%Y-%m-%d)). Не править руками — правьте .jsx и пересоберите." > "$OUT"
for f in ui Home Guide Catalog ProductSheet Search app; do
  echo "// ---- $f.jsx ----" >> "$OUT"
  npx --yes esbuild@0.25.10 "$f.jsx" --loader:.jsx=jsx --jsx=transform --target=es2019 --log-level=warning >> "$OUT"
done
echo "OK: $OUT"
