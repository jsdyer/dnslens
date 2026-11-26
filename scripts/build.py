"""Build the standalone GitHub Pages site."""

from pathlib import Path
import json
import shutil
from search_pages import render_pages, PAGES


root = Path(__file__).resolve().parent.parent
web = root / "web"
dist = root / "dist"
required = ("index.html", "style.css", "app.mjs", "model.mjs")
for filename in required:
    if not (web / filename).is_file():
        raise SystemExit(f"Missing application asset: {filename}")
if dist.exists():
    shutil.rmtree(dist)
shutil.copytree(web, dist)
render_pages(dist, json.loads((root / "tool.json").read_text()), PAGES)
print("Built dist.")
