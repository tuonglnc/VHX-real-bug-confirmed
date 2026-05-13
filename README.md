# VHX-real-bug-confirmed

A collection of real-world vulnerabilities discovered by the [VulnHunterX Framework](https://github.com/vinsoc-cyber/VulnHunterX).

Each vulnerability is manually verified, analyzed in detail, and accompanied by evidence (PoC, data flow, reasoning). When a vendor confirms the issue, the corresponding proof of confirmation is also stored here.

---

## Directory Structure

```
libraries/
└── <language>/
    └── <library>/
        ├── report.md                # Full vulnerability report
        ├── summary_<library>_<timestamp>.json   # Scan metadata
        └── <vulnerability-name>/
            ├── VulnHunterX/         # Raw VulnHunterX scan output
            │   ├── report.md
            │   ├── <rule>_<id>.json
            │   └── llm_conversations.md
            └── manual_confirm/      # Manual verification & vendor confirmation
                └── <vulnerability-name>.md
```

---

## Confirmed Vulnerabilities

> Only vulnerabilities with manual confirmation (PoC / detailed analysis) are listed here.

### C

| Library | Vulnerability | File | CWE | Report | Vendor |
|---------|--------------|------|-----|--------|--------|
| **flac** | TOCTOU Race Condition | `src/share/grabbag/file.c:116` | CWE-367 | [report](libraries/c/flac/flac_toctou-race-condition/manual_confirm/flac_toctou-race-condition.md) | [xiph/flac#902](https://github.com/xiph/flac/issues/902) |
| **libevent** | Compiler-Elidable memset() | `sha1.c:202` | CWE-14 | [report](libraries/c/libevent/libevent-memset-maybe-deleted/manual_confirm/libevent_menset-may-be-deleted.md) | advance-security (triage) |
| **vorbis** | Stack Overflow via alloca() in Loop | `lib/vorbisfile.c:2290` | CWE-770 | [report](libraries/c/vorbis/vorbis_alloca-stack-overflow/manual_confirm/vorbis_alloca-stack-overflow.md) | [MR !43](https://gitlab.xiph.org/xiph/vorbis/-/merge_requests/43) |

### Python

| Library | Vulnerability | File | CWE | Report | Vendor |
|---------|--------------|------|-----|--------|--------|
| **gradio** | Full SSRF via User-Controlled URL | `gradio/image_utils.py:253` | CWE-918 | [report](libraries/python/gradio/manual_confirm/full-ssrf.json) | Security GitHub (triage, private) |
| **safety** | Credential Leak via Incomplete URL Substring Sanitization | `safety/tool/uv/command.py:72` | CWE-295 | [report](libraries/python/safety/safety_incomplete-url-substring-sanitization/manual_confirm/safety_incomplete-url-substring-sanitization.md) | email (triage) |

---

## Teamwork Guidelines

### Workflow

1. **Tạo branch mới** từ `main` cho mỗi vulnerability hoặc thay đổi:
   ```bash
   git checkout main && git pull
   git checkout -b <tên-branch>
   ```
   Tên branch gợi ý: `<library>-<vulnerability-name>`, ví dụ `flac-toctou-race-condition`.

2. **Làm việc trên branch**, commit khi hoàn thành một đơn vị logic.

3. **Tạo PR** để review trước khi merge vào `main`.

4. **Merge** — squash merge hoặc merge commit đều được.

### Commit Convention

- Dùng tiếng Anh, câu lệnh (imperative), không dấu chấm cuối:
  - `Add analysis for flac TOCTOU race condition`
  - `Fix poc buffer overflow in libevent`
  - `Update vendor confirmation for gradio`
- Prefix phổ biến: `Add`, `Update`, `Fix`, `Remove`
- Mỗi commit nên là một thay đổi logic duy nhất (atomic commit).

### Folder Structure

Each vulnerability should be placed in its own folder following the structure below, with at least an `analysis.md` containing:

1. **Description** — vulnerability type, location in source code
2. **Data flow** — data flow from source to sink
3. **Impact** — consequences if exploited
4. **PoC** — exploit code or reproduction steps (if available)
5. **Vendor confirmation** — advisory link, email correspondence (if confirmed by vendor)

## License

MIT — see [LICENSE](LICENSE).
