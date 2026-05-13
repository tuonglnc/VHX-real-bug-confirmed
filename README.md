# VHX-real-bug-confirmed

A collection of real-world vulnerabilities discovered by the [VulnHunterX Framework](https://github.com/vinsoc-cyber/VulnHunterX).

Each vulnerability is manually verified, analyzed in detail, and accompanied by evidence (PoC, data flow, reasoning). When a vendor confirms the issue, the corresponding proof of confirmation is also stored here.

---

## Directory Structure

```
libraries/
└── <language>/
    └── <library>/
        └── <vulnerability-name>/
            ├── analysis.md          # Detailed vulnerability analysis (data flow, reasoning, impact)
            ├── poc/                 # Proof of Concept / exploit code
            ├── vendor-confirm/      # Vendor confirmation evidence (if available)
            │   ├── email.md         # Communication with vendor
            │   ├── advisory.md      # Vendor security advisory
            │   └── ...
            └── ...
```

### Example

```
libraries/
└── c/
    ├── flac/
    │   ├── report.md
    │   ├── summary_flac_20260512_130300.json
    │   └── toctou-race-condition/
    │       ├── analysis.md
    │       ├── poc/
    │       └── vendor-confirm/
    │           ├── advisory.md
    │           └── ...
    └── libevent/
        ├── report.md
        ├── summary_libevent_20260512_080137.json
        └── memset-deleted/
            ├── analysis.md
            └── ...
└── python/
    ├── gradio/
    └── safety/
```

---

## Confirmed Vulnerabilities

### C

| Library | Vulnerability | File | CWE | Vendor | Report |
|---------|--------------|------|-----|:------:|--------|
| **flac** | TOCTOU Race Condition | `src/share/grabbag/file.c:116` | CWE-367 | | |
| **libevent** | memset Deleted by Compiler | `sha1.c:202` | CWE-14 | | |


### Python

| Library | Vulnerability | File | CWE | Vendor | Report |
|---------|--------------|------|-----|:------:|--------|
| | | | | | |

---

## Contributing

Each vulnerability should be placed in its own folder following the structure above, with at least an `analysis.md` containing:

1. **Description** — vulnerability type, location in source code
2. **Data flow** — data flow from source to sink
3. **Impact** — consequences if exploited
4. **PoC** — exploit code or reproduction steps (if available)
5. **Vendor confirmation** — advisory link, email correspondence (if confirmed by vendor)

## License

MIT — see [LICENSE](LICENSE).
