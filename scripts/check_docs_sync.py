#!/usr/bin/env python3
"""
FakeSpotter — check_docs_sync.py
Pre-merge gate: verifica que EXPECTED_TOOLS en ci_check.py coincide
con el conteo de tools declarado en README.md.

Falla (exit 1) si hay divergencia, para bloquear el merge en CI.

Uso:
    python scripts/check_docs_sync.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── 1. Leer EXPECTED_TOOLS de ci_check.py ───────────────────────────────────

ci_check = (ROOT / "scripts" / "ci_check.py").read_text()
m = re.search(r"EXPECTED_TOOLS\s*=\s*(\d+)", ci_check)
if not m:
    print("❌  EXPECTED_TOOLS no encontrado en scripts/ci_check.py", file=sys.stderr)
    sys.exit(1)

expected_tools = int(m.group(1))

# ── 2. Leer conteo de tools del README ──────────────────────────────────────

readme = (ROOT / "README.md").read_text()

# Busca el patrón "N tools" en el tagline del header (primera ocurrencia)
m2 = re.search(r"(\d+)\s+tools", readme)
if not m2:
    print("❌  No se encontró 'N tools' en README.md", file=sys.stderr)
    sys.exit(1)

readme_tools = int(m2.group(1))

# ── 3. También verificar la sección de arquitectura ─────────────────────────

arch_matches = re.findall(r"FastMCP exposes (\d+) forensic modules", readme)
arch_count = int(arch_matches[0]) if arch_matches else None

# ── 4. Comparar ─────────────────────────────────────────────────────────────

errors: list[str] = []

if readme_tools != expected_tools:
    errors.append(
        f"  README tagline dice {readme_tools} tools, "
        f"ci_check.py EXPECTED_TOOLS={expected_tools}"
    )

if arch_count is not None and arch_count != expected_tools:
    errors.append(
        f"  README Architecture section dice {arch_count} forensic modules, "
        f"ci_check.py EXPECTED_TOOLS={expected_tools}"
    )

if errors:
    print("❌  Docs out of sync with ci_check.py:\n" + "\n".join(errors), file=sys.stderr)
    print(
        "\nFix: update README.md tool counts to match EXPECTED_TOOLS "
        f"({expected_tools}) in scripts/ci_check.py, then re-run.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"✅  Docs in sync — {expected_tools} tools declared in README and ci_check.py")
sys.exit(0)
