# FakeSpotter — Roadmap

*Última actualización: 2026-09-06*

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

