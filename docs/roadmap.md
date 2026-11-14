# FakeSpotter — Roadmap

*Última actualización: 2026-11-14*

## Arco completado (S1–S10)

| Sprint | PR | Descripción |
|--------|----|-------------|
| S1 · FS-02 | #42 | README: tools de medios a sección Research; Invoice Guard como hero |
| S2 · FS-01 | #43 | `server.py`: instructions lideradas por Invoice Guard |
| S3 · FS-04 | #44 | `eval_deterministic.py` + `docs/accuracy.md` (FP/FN reales) |
| S5 · FS-05 | #45 | `src/backends/`: neural ensemble imagen (HF × 2 + Sightengine) |
| S6 · FS-06 | #46 | `src/backends/`: audio, texto, SynthID; `utils/audio.py` (OGG/M4A/WebM/AMR) |
| S7         | #47 | `detect_ai_generated_music` — tool #19; atribución Suno/Udio/Riffusion |
| S8         | #48 | Corpus versionado, `health_check.py`, workflow mensual de obsolescencia |
| S9 · FS-03 | #49 | README reescrito con `⚠️ Declared Limits`; arco S1–S9 cerrado |
| S10        | #50 | Entropy weight 15→25 pts; URL reputation threshold 25→35 pts; FP/FN 0% |

**Estado actual:** 19 tools · 4 capas · BYOK en todo · health check mensual automático

---

## Roadmap S11–S19 — COMPLETADO ✅

### S11 — `inspect_qr_code` · tool #20

Detecta y decodifica QR codes en imágenes y PDFs. Extiende Invoice Guard: una factura puede tener hash íntegro pero el QR apunta a un CBU/cuenta diferente al texto del documento.

**Flujo:**
1. Descarga imagen o PDF
2. PDFs: rasteriza páginas con PyMuPDF → detecta QR con OpenCV
3. Parsea contenido (URL, CBU/CVU, IBAN, CLABE, texto libre)
4. Con `expected_data`: comparación determinista → `QR_MATCH` / `QR_MISMATCH`
5. Sin `expected_data`: devuelve contenido decodificado para revisión humana

**Verdicts:** `QR_MATCH` · `QR_MISMATCH` · `QR_DECODED` · `NO_QR_FOUND`

**Nueva dep:** `pymupdf>=1.24,<2`

---

### S12 — `verify_digital_signature` · tool #21

Valida firmas digitales PKCS#7/CMS embebidas en PDFs (Adobe Acrobat, DocuSign, contratos firmados electrónicamente). Verifica identidad del firmante y que el documento no fue modificado post-firma.

**Hallazgos en certificado:**
- Identidad del firmante (CN, Organización, País)
- Período de validez del certificado X.509
- Cobertura de la firma (todo el documento vs. parcial)
- Modificaciones detectadas post-firma
- Número de firmas y orden

**Verdicts:** `SIGNATURE_VALID` · `SIGNATURE_INVALID` · `SIGNATURE_EXPIRED` · `DOCUMENT_MODIFIED_AFTER_SIGNING` · `NO_SIGNATURE_FOUND`

**Nueva dep:** `pyhanko>=0.20,<1` · `cryptography>=42,<44`

> **Nota (2026-11):** hasta S25 (PR #95) esta tool devolvía `SIGNATURE_INVALID` para todo PDF firmado (llamaba a la validación síncrona de pyHanko dentro del event loop). Corregido y cubierto por `tests/test_signatures_timestamps.py`; límites vigentes (trust roots, LTV) en README → Declared Limits.

---

### S13 — `validate_bank_account` · tool #22

Validación matemática de números de cuenta bancaria por checksum. Determinista — cero FP/FN por construcción, igual que `verify_document_integrity`.

**Formatos soportados:**

| Formato | Algoritmo | Región |
|---------|-----------|--------|
| IBAN | mod 97 | SEPA + global (77 países) |
| CBU | dos dígitos verificadores | Argentina |
| CVU | misma lógica que CBU | Argentina (billeteras virtuales) |
| CLABE | pesos publicados CNBV | México |
| BBAN | validación estructural | Europa (no-IBAN) |

**Sin dependencias externas.** Pura aritmética, reproducible offline.

**Verdicts:** `CHECKSUM_VALID` · `CHECKSUM_INVALID` · `FORMAT_UNRECOGNIZED`

---

### S14 — `validate_mrz` · tool #23

Verifica la Machine Readable Zone (MRZ) de pasaportes, cédulas de identidad y visas según el estándar ICAO Doc 9303. Cada campo tiene checksum propio — si alguien editó un dígito, el checksum falla matemáticamente.

**Campos verificados:**
- Número de documento (dígito verificador)
- Fecha de nacimiento (dígito verificador)
- Fecha de expiración (dígito verificador)
- Número compuesto (cubre múltiples campos)
- Tipo de documento y código de país (validación estructural)

**Verdicts:** `MRZ_VALID` · `MRZ_CHECKSUM_FAILED` · `MRZ_FORMAT_INVALID`

**Nueva dep:** `passporteye>=2.2,<3`

---

### S15 — `analyze_pdf_metadata` · tool #24

Forense de metadatos internos de un PDF. Sin necesidad de firma digital — detecta inconsistencias temporales y de software que revelan manipulación.

**Señales analizadas:**
- `CreationDate` vs `ModDate` — un contrato de 2022 con ModDate de 2026 es una señal
- `Producer` — ¿LibreOffice en un documento que debería ser de Adobe Acrobat?
- `Author` vs identidad declarada en el texto
- Versiones internas del PDF (un bump de versión post-fecha de emisión es detectable)
- `PermsHandler` — permisos que revelan modificaciones post-restricción

**Sin dependencias nuevas** — usa `pymupdf` incorporado en S11.

**Verdicts:** `METADATA_CONSISTENT` · `METADATA_INCONSISTENT` · `METADATA_SUSPICIOUS`

---

### S16 — `verify_c2pa_manifest` · tool #25

Lee y verifica manifiestos C2PA (Coalition for Content Provenance and Authenticity, ISO/IEC 22144) embebidos en imágenes, audio y video. Más de 6.000 organizaciones adoptaron el estándar en 2026, incluyendo Adobe, Google, Meta, Microsoft y OpenAI.

**Qué verifica:**
- Integridad criptográfica del manifiesto (si fue alterado post-generación)
- Herramienta que creó el archivo (Photoshop, DALL-E, Firefly, etc.)
- Historial de ediciones declaradas
- Presencia/ausencia de manifiesto (ausencia no implica falsedad)

**Diferenciador:** ningún servidor MCP publicado tiene esta tool hoy. Complementa el ensemble neural (S5–S7) con provenance criptográficamente verificable.

**Nueva dep:** `python-c2pa>=0.5,<1`

---

### S17 — upgrade `scan_phishing_url`

No agrega tool — mejora la existente añadiendo detección de typosquatting que hoy escapa al scoring por keyword.

**Nuevas señales:**
- **Levenshtein ≤ 2** contra whitelist de ~500 dominios conocidos (paypal, amazon, google, etc.) → +35 pts
- **Homograph detection** — caracteres Unicode confundibles: ρ→p, 0→O, l→I, rn→m, vv→w → +40 pts
- **IDN spoofing** — dominios internacionalizados que visualizan igual a dominios latinos

**Sin dependencias nuevas** — `difflib` es stdlib Python.

---

### S18 — `validate_identity_liveness` · tool #26

KYC en dos pasos: verifica que la foto del documento de identidad corresponde a la selfie del solicitante y que la selfie es de una persona real (liveness detection).

**Backends BYOK (Sightengine, free tier):**
- `models=liveness` — detecta foto de foto, pantalla, máscara, imagen impresa
- `models=face-attributes` — compara rasgos faciales entre documento y selfie

**Parámetros:** `document_url` · `selfie_url` · `se_user` · `se_secret`

**Verdicts:** `LIVENESS_CONFIRMED` · `LIVENESS_FAILED` · `FACE_MATCH` · `FACE_MISMATCH` · `FACE_NOT_DETECTED`

---

### S19 — `correlate_documents` · tool #27

Dado un conjunto de documentos, detecta reutilización de imágenes entre archivos. Un template de factura falso reutilizado en múltiples estafas deja huella criptográfica y perceptual.

**Flujo:**
1. Descarga hasta 10 documentos (imágenes o PDFs)
2. Extrae imágenes embebidas de cada PDF
3. Calcula pHash y dHash de cada imagen
4. Construye matriz de similitud (Hamming distance)
5. Detecta clusters de documentos que comparten assets

**Output:** matriz de similitud + lista de pares/grupos con assets compartidos + hashes para auditoría.

**Verdicts:** `NO_CORRELATION` · `ASSETS_SHARED` (con lista de pares)

**Nueva dep:** `imagehash>=4.3,<5`

---

## Tabla de dependencias por sprint

| Sprint | Deps nuevas | Deps reutilizadas |
|--------|-------------|-------------------|
| S11 | `pymupdf` | `opencv-python-headless` (ya en requirements) |
| S12 | `pyhanko`, `cryptography` | — |
| S13 | ninguna | — |
| S14 | `passporteye` | — |
| S15 | ninguna | `pymupdf` (S11) |
| S16 | `python-c2pa` | — |
| S17 | ninguna | stdlib `difflib` |
| S18 | ninguna | Sightengine BYOK (ya en backends) |
| S19 | `imagehash` | `pymupdf` (S11) |

---

## Estado de tools al completar S19

| # | Tool | Tipo | Sprint |
|---|------|------|--------|
| 1–4 | Invoice Guard (4 tools) | Determinista | S1–S2 |
| 5–12 | Toolkit determinista (8 tools) | Determinista | S1 |
| 13–17 | AI Detection (5 tools) | Neural BYOK | S5–S7 |
| 18–19 | Layer-1 heurístico (2 tools) | Heurístico | S1 |
| 20 | `inspect_qr_code` | Determinista | S11 |
| 21 | `verify_digital_signature` | Determinista | S12 |
| 22 | `validate_bank_account` | Determinista | S13 |
| 23 | `validate_mrz` | Determinista | S14 |
| 24 | `analyze_pdf_metadata` | Determinista | S15 |
| 25 | `verify_c2pa_manifest` | Estándar ISO | S16 |
| 26 | `validate_identity_liveness` | Neural BYOK | S18 |
| 27 | `correlate_documents` | Determinista | S19 |

**Total: 27 tools — arco S11–S19 cerrado** ✅


---

## Arco S20–S22

### S20 — `verify_rfc3161_timestamp` · tool #28

Verifica tokens RFC 3161 emitidos por una TSA (Timestamp Authority). Usa `pyhanko` (ya en requirements). Complementa `verify_digital_signature` con timestamps cualificados independientes del firmante.

Input: `pdf_url` (extrae TSTs embebidos), `tsr_url` (archivo .tsr), `tsr_hex` (token inline).
Verdicts: `TIMESTAMP_VALID` · `TIMESTAMP_INVALID` · `TIMESTAMP_EXPIRED` · `NO_TIMESTAMP_FOUND`
**Sin dependencias nuevas.**

> **Nota (2026-11):** hasta S25 (PR #95) esta tool fallaba con `ImportError` ante cualquier token y nunca encontraba los timestamps embebidos en un PDF. Corregido y cubierto por `tests/test_signatures_timestamps.py`. En el mismo cambio se corrigieron `validate_bank_account` (auto-detección, dígitos CBU/CVU), `validate_mrz` (dígito compuesto TD3), `analyze_pdf_metadata` (fechas), `correlate_documents` (`hamming_threshold`), `analyze_url_reputation` y el modo quick de las tools de red.

---

### S21 — `analyze_email_thread` · tool #29

Detecta manipulación de hilos de email (vector BEC). Sin dependencias externas — stdlib puro.

Señales: thread insertion (un mensaje referencia un Message-ID con fecha posterior — físicamente imposible), Reply-To hijacking, Date vs Received gap >48h, Message-ID duplicados, referencias a IDs desconocidos, sujeto inconsistente, remitentes nuevos mid-thread.
Verdicts: `THREAD_INTACT` · `THREAD_SUSPICIOUS` · `THREAD_MANIPULATED`
**Sin dependencias nuevas.**

---

### S22 — Docs sprint

Actualiza README (29 tools, tabla completa de toolkit determinista con S11–S21), roadmap con S20–S22, sección Declared Limits. No agrega tools.

---

## Estado final al cierre de S22

**29 tools · 22 sprints**

---

## Arco S20–S23 (ejecutado) ✅

> **Corrección (2026-11-14):** una versión anterior de esta tabla atribuía S20–S22 a los PRs #77, #79 y #80. Eso era incorrecto: #77 y #80 son PRs de Dependabot (uvicorn, cryptography) mergeados recién el 2026-11-14. Las filas siguientes reflejan el historial real de git.

| Sprint | PR | Descripción |
|--------|----|-------------|
| —   | #72 | Migración de `signature_tools.py` a la API de pyHanko 0.37 |
| S20 | #73 | `verify_rfc3161_timestamp` — tool #28 (ver nota en la sección S20: no funcionaba hasta S25) |
| S21 | #74 | `analyze_email_thread` — tool #29 |
| S22 | `833a77e` (commit directo, sin PR) | Docs: README + roadmap actualizados para 29 tools |
| S23 | #82 | Cierra brecha README vs realidad — `HFAudioBackend` wired en `analyze_audio_authenticity`; `HFTextBackend` wired en `detect_ai_generated_text`; `hf_token` añadido a ambos inputs; fallback `LAYER_1_FALLBACK` explícito; `scripts/regression_test.py` (19 tests); paso de regresión añadido a CI |

**Estado al cierre de S23:** 29 tools · 5/5 neural-ensemble tools realmente cableadas · CI: arranque + inventario + regresión

---

## Arco S24 ✅

### S24 — Docs sync + pre-merge gate · PR #83

Elimina divergencia entre roadmap/README y el estado real del repo. Implementa validación automática pre-merge.

**Cambios:**
- README: 19→29 tools; arquitectura actualizada; marcas "Fix pending" → resueltas en S10
- `roadmap.md`: arco S20–S23 ejecutado documentado
- `scripts/check_docs_sync.py`: valida que `EXPECTED_TOOLS` en `ci_check.py` coincide con el conteo declarado en README
- `.github/workflows/ci.yml`: paso `check_docs_sync` como gate obligatorio pre-merge

**Después de S24:** PR #93: `classifier-health.yml` con permisos corregidos; se salta sin error si falta el token de HF.

---

## Arco S25: mantenimiento, tests reales y corrección de bugs (2026-11-14)

### Auditoría de cobertura (punto de partida)

Antes de S25 solo 2 de las 29 tools tenían tests que verificaban su resultado. `scripts/regression_test.py` reemplaza Pillow, PyMuPDF, pyHanko y demás librerías pesadas por stubs (`MagicMock`), así que no podía detectar ni upgrades ni bugs reales. `ci_check.py` solo contaba tools. `eval_deterministic.py` evaluaba una copia de la lógica en vez del código real, y esa copia ya había divergido.

### Dependencias (sobre `main`)

| PR | Cambio |
|----|--------|
| #77, #80, #81, #86, #87, #90, #91 | Dependabot menores: uvicorn, cryptography, python-dotenv, numpy, pydantic, pyhanko, c2pa-python |
| #94 | **Migración a mcp 2.x** (`FastMCP` → `MCPServer`); el bind HTTP explícito a `0.0.0.0` hace falta en 2.x. Listado de tools y resultados idénticos byte a byte a 1.x. `ci_check.py` verifica los 29 nombres exactos. Reemplaza a #84 (cerrado) |

### S25 · PR #95

**Suite de tests real (`tests/`, pytest): 203 tests, offline y deterministas.**
- Llama a las tools reales a través del cliente MCP público, con las librerías reales: `conftest.py` falla si hay stubs.
- Los fixtures se generan en tiempo de test: PKI de prueba, PDFs firmados con pyHanko, TSA local, QR e imágenes. No se commitean binarios.
- Cubre Invoice Guard, cuentas bancarias, MRZ, firmas y timestamps, metadatos PDF, QR, correlación, hilos de email e inventario de tools.
- `eval_deterministic.py` ahora usa las tools reales, con un nuevo flag `--skip-live`.

**Bugs corregidos.** Todos existían en producción y cada uno tenía un test que fallaba antes del fix:

| Tool | Bug | Efecto antes del fix |
|------|-----|----------------------|
| `verify_digital_signature` | Validación síncrona de pyHanko dentro del event loop; import faltante | Todo PDF firmado → `SIGNATURE_INVALID` |
| `verify_rfc3161_timestamp` | Import incorrecto; llamada sin `await`; extracción de PDF rota | Fallaba con cualquier token; con PDF nunca funcionó |
| `check_email_headers` (+ modo quick de `scan_phishing_url` y `analyze_url_reputation`) | El helper de modo quick no reconocía los verdicts de estas tools | Siempre "UNCERTAIN", sin verdict (modo por defecto) |
| `analyze_url_reputation` | Capturaba `httpx.ConnectSSLError`, que no existe | Error en vez de verdict ante cualquier fallo de conexión |
| `validate_bank_account` | Auto-detección con mayúsculas/minúsculas; pesos BCRA incorrectos en CBU/CVU | `format="auto"` rechazaba IBAN/CLABE válidos; CBU/CVU reales rechazados |
| `validate_mrz` | Dígito compuesto TD3 leído en la posición equivocada | El espécimen ICAO TD3 fallaba |
| `analyze_pdf_metadata` | `strptime` sobre input recortado | Horas alteradas, offset UTC perdido, XMP nunca parseado |
| `correlate_documents` | `hamming_threshold` nunca se usaba | El umbral se ignoraba |

`SIGNATURE_EXPIRED` y `TIMESTAMP_EXPIRED` ahora son alcanzables y tienen tests. El parseo de fechas PDF ya no depende de la versión de Python.

**Upgrades:**
- Pillow `>=13,<14` y pymupdf `>=2.1,<3`, sin cambios de resultados. `import fitz` → `import pymupdf`. Reemplazan a #92 y #89 (cerrados).
- Nota: pymupdf 2.x arrastra onnxruntime, y la imagen crece.

**CI:**
- Job nuevo de `docker build` + smoke test: `initialize` + `tools/list` = 29 tools.
- Job experimental de Python 3.15, solo en ejecución manual (`workflow_dispatch`): en cada PR solo podía mostrar un check rojo.
- `ci_check.py` verifica los nombres exactos de las 29 tools.

**Configuración y docs:**
- Dockerfile con `ENV PORT=8000`, la variable que el servidor realmente lee. Antes escuchaba en 8081 aunque exponía 8000.
- `check_docs_sync.py` ahora falla si falta la frase del README, en vez de pasar en silencio.
- `docs/accuracy.md` regenerado con las tools reales. URL reputation queda como "no medido": su 0% anterior venía de la copia de la lógica.
- README → Declared Limits actualizado: trust roots y sin LTV en firmas, checks solo de checksum, fechas PDF sin offset.

**Estado al cierre de S25:** 29 tools · mcp 2.x · 203 tests con librerías reales en CI (3.13 + 3.14) · 0 xfail

---

## Pendiente

- **Python 3.15** (#88, abierto a propósito): bloqueado porque onnxruntime (vía pymupdf 2.x) no tiene wheels cp315, y scikit-image (vía passporteye) tampoco, ni compila en la imagen slim. Un chequeo semanal en PyPI avisa cuando estén disponibles.
- **Medir URL reputation** con `python scripts/eval_deterministic.py` desde un host con acceso directo a internet.
- **Límites conocidos** (documentados):
  - En `analyze_url_reputation`, un error TLS solo sigue dando `GOOD_REPUTATION`, y un error de proxy no suma puntos.
  - Firmas sin trust roots configurables y sin LTV.
  - Sin análisis de actualizaciones incrementales posteriores a la firma.
  - MRZ sin TD2.
- **`serverInfo.version`** vacío desde mcp 2.x (se puede fijar con `MCPServer(version=...)`).
