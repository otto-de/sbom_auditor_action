# Intelligent License Resolution

## Überblick

Das SBOM Auditor Action wurde um eine **intelligente License Resolution** erweitert, die automatisch unbekannte oder nicht-standardisierte Lizenz-Namen zu korrekten SPDX-Identifiern auflöst.

## Problem

Maven Central und andere Package-Repositories verwenden oft beschreibende Lizenz-Namen anstelle von standardisierten SPDX-Identifiern:

- `"Eclipse Public License v2.0"` → sollte `"EPL-2.0"` sein
- `"The Apache Software License, Version 2.0"` → sollte `"Apache-2.0"` sein  
- `"BSD 3-Clause License"` → sollte `"BSD-3-Clause"` sein

Dies führt dazu, dass diese Lizenzen als "non-standard" oder "needs-review" markiert werden, obwohl sie bekannte und erlaubte Lizenzen sind.

## Lösung

### Hybrides Resolution-System

1. **SPDX Pattern Matching** (Primär)
   - Lädt die offizielle SPDX License List von GitHub
   - Normalisiert Lizenz-Namen (entfernt "The", "License", etc.)
   - Verwendet vordefinierte Regex-Pattern für häufige Fälle
   - Fuzzy-String-Matching mit konfigurierbarem Threshold

2. **AI-Powered Fallback** (Optional)
   - GitHub Models API für schwierige Fälle
   - Unterstützt OpenAI, Azure, AWS Bedrock
   - Nur wenn SPDX-Matching fehlschlägt

### Neue Dateien

- **`license_resolver.py`**: Core-Klasse für License Resolution
- **`enhanced_license_enricher.py`**: Erweiterte SBOM-Anreicherung mit Resolution
- **`enrich_sbom_enhanced.py`**: Erweiterte Version von `enrich_sbom.py`
- **`audit_licenses_enhanced.py`**: Erweiterte Version von `audit_licenses.py`

## Verwendung

### 1. SBOM Enrichment mit License Resolution

```bash
# Automatische Resolution aktiviert (Standard)
python enrich_sbom_enhanced.py input.json output.json

# Resolution deaktivieren
python enrich_sbom_enhanced.py input.json output.json --no-resolve-licenses
```

### 2. License Audit mit Resolution

```bash  
# Mit Resolution (Standard)
python audit_licenses_enhanced.py sbom.json policy.json

# Mit AI Summary
python audit_licenses_enhanced.py sbom.json policy.json --generate-summary

# Resolution deaktivieren
python audit_licenses_enhanced.py sbom.json policy.json --no-resolve-licenses
```

### 3. Standalone License Resolution

```python
from license_resolver import LicenseResolver

resolver = LicenseResolver()
result = resolver.resolve_license("Eclipse Public License v2.0")

print(result)
# {
#   'original': 'Eclipse Public License v2.0',
#   'resolved': 'EPL-2.0', 
#   'method': 'spdx_fuzzy',
#   'confidence': 0.9
# }
```

## Konfiguration

### Umgebungsvariablen

- **`GITHUB_TOKEN`**: Für AI-powered Fallback (optional)

### Parameter

- **`--resolve-licenses`**: Aktiviert Resolution (Standard: true)
- **`--no-resolve-licenses`**: Deaktiviert Resolution
- **`--debug`**: Detaillierte Logs

## Resolution-Methoden

| Methode | Beschreibung | Beispiel |
|---------|--------------|----------|
| `spdx_fuzzy` | SPDX Pattern/Fuzzy Matching | `"MIT License"` → `"MIT"` |
| `ai_assisted` | AI-powered Recognition | Komplexe/ungewöhnliche Namen |
| `unresolved` | Keine Resolution möglich | Bleibt "needs-review" |

## Erweiterte Metadaten

Die Resolution fügt zusätzliche Metadaten zu SBOM-Paketen hinzu:

```json
{
  "name": "example-package",
  "licenseConcluded": "EPL-2.0",
  "enrichment": {
    "licenseResolution": {
      "original": "Eclipse Public License v2.0",
      "resolved": "EPL-2.0",
      "method": "spdx_fuzzy",
      "confidence": 0.9
    }
  }
}
```

## Pattern Recognition

### Häufige Pattern

- Apache: `apache.*license.*v?\.?2\.?0?` → `Apache-2.0`
- Eclipse: `eclipse.*public.*license.*v?\.?2\.?0?` → `EPL-2.0`
- MIT: `mit.*license` → `MIT`  
- BSD: `bsd.*3.*clause` → `BSD-3-Clause`
- GPL: `gnu.*general.*public.*license.*v?\.?3` → `GPL-3.0-only`

### Normalisierung

1. Lowercase-Konvertierung
2. Entfernung von "The", Kommas, Klammern
3. Vereinheitlichung von "License"/"Licence"
4. Version-Pattern-Normalisierung (`v2.0`, `version 2.0` → `v2.0`)

## Statistiken und Reporting

```
📊 License Resolution Report:
========================================
   spdx_fuzzy: 156 (87.2%)
   ai_assisted: 12 (6.7%)  
   unresolved: 11 (6.1%)
   Total: 179
```

## Migration

### Upgrade zu Enhanced Versions

```bash
# Automatisches Upgrade
python upgrade_license_resolution.py

# Rollback
python upgrade_license_resolution.py --rollback
```

### Backward Compatibility

- Bestehende Scripts funktionieren weiterhin
- Resolution ist standardmäßig aktiviert
- Kann mit `--no-resolve-licenses` deaktiviert werden

## Testing

```bash
# Test License Resolution
python license_resolver.py

# Test Integration  
python test_license_resolution.py

# Test Enhanced Enrichment
python enhanced_license_enricher.py
```

## Performance

- **SPDX-Daten**: 703 Lizenzen, einmalig geladen und gecacht
- **Pattern Matching**: ~1ms pro Lizenz
- **AI Fallback**: ~500ms pro Aufruf (nur bei Bedarf)
- **Cache**: LRU-Cache für wiederholte Anfragen

## Vorteile

1. **Automatische Compliance**: Weniger "needs-review" Fälle
2. **Standardisierung**: Konsistente SPDX-Identifiers
3. **Hybrid-Ansatz**: Robust und zuverlässig
4. **Konfigurierbar**: Kann nach Bedarf aktiviert/deaktiviert werden  
5. **Transparent**: Vollständige Nachverfolgung der Resolution
6. **Performant**: Intelligente Caching-Strategien

## Beispiel-Output

```
🧪 Testing License Resolver
==================================================
📝 'Eclipse Public License v2.0'
   → EPL-2.0 (spdx_fuzzy, confidence: 0.9)

📝 'The Apache Software License, Version 2.0'  
   → Apache-2.0 (spdx_fuzzy, confidence: 0.9)

📝 'BSD 3-Clause License'
   → BSD-3-Clause (spdx_fuzzy, confidence: 0.9)
```

## Nächste Schritte

1. **Weitere Pattern**: Ergänzung um zusätzliche häufige Lizenz-Varianten
2. **Learning System**: Automatisches Lernen aus erfolgreichen Resolutions
3. **Custom Mappings**: Benutzer-definierte Mappings für spezielle Fälle
4. **Confidence Tuning**: Optimierung der Confidence-Thresholds
