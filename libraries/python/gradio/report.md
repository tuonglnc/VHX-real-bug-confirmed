# VulnHunterX Verification Report

**Generated**: 2026-05-12 16:40:27  
**Repository**: gradio  
**Language**: python  
**Model**: glm-5.1  
**Provider**: openai  

---

## Executive Summary

| Metric | Count | Percentage |
|--------|------:|-----------:|
| Total Findings | 49 | 100% |
| True Positive | 24 | 49.0% |
| False Positive | 12 | 24.5% |
| Needs More Data | 1 | 2.0% |
| Errors | 12 | 24.5% |

**False Positive Rate**: 24.5%  
**Total Verification Time**: 1618.8s  
**Total Tokens**: 224,376  
**Total Cost**: $0.0000  

---

## Severity Breakdown

| Severity | TP | FP | NMD | Total |
|----------|---:|---:|----:|------:|
| 7.5 | 22 | 10 | 1 | 45 |
| 9.1 | 2 | 0 | 0 | 2 |
| 6.1 | 0 | 2 | 0 | 2 |


---

## Findings Detail

### True Positives (24)

#### 1. py/path-injection @ gradio/image_utils.py:257

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 23.3s |
| **Tokens** | 4,199 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source (user-provided value from Gradio component, multiple paths via lines 21/17/49/23 in external files) → transform (through value/initial_value/load_fn chain) → `image_file` parameter (line 243) → `str()` conversion (line 244) → sink: `open(image_file)` (line 252) reads arbitrary file content

**Reasoning**: The `extract_svg_content` function takes an `image_file` parameter that CodeQL has traced through multiple dataflow paths back to user-provided Gradio component values. In the non-URL branch (line 251-254), the value is passed directly to `open()` with no path traversal checks — no sanitization of '../' sequences, no path normalization, no verification against an allowed base directory. This enables arbitrary file read on the server. The high precision rating of the rule and severity of 7.5 further support this being a genuine vulnerability.

**Guided Question Answers**:

1. The path input originates from user-provided values traced through Gradio component data flow (multiple flows through 'value', 'initial_value', etc. from UI component attributes — sources at lines 21, 17, 49, 23 in external files). The `image_file` parameter of `extract_svg_content` ultimately derives from these user-provided values. In the provided code, `image_file` is received as a function parameter on line 243.
2. No `os.path.join()` is used. The `image_file` is converted to a string on line 244 and then passed directly to `open()` on line 252 or used in `httpx.get()` on line 248 without any path joining or construction.
3. No normalization is performed. There is no call to `os.path.realpath()`, `os.path.abspath()`, `pathlib.resolve()`, or any equivalent. The string conversion on line 244 (`image_file = str(image_file)`) is purely a type cast, not a security normalization.
4. No. There is no check that the resolved path starts with an allowed base directory. No allowlist, no prefix check, no chroot validation exists anywhere in the function.
5. Yes. Since `image_file` flows directly from user input through Gradio's data pipeline with no sanitization or validation, an attacker could supply paths containing '../' sequences or absolute paths like '/etc/passwd' to read arbitrary files on the server.
6. A READ operation is performed: `open(image_file)` on line 252 reads the file contents via `file.read()` on line 253. This enables arbitrary file read (not write or delete).

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 257: ControlFlowNode for image_file
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 257: ControlFlowNode for image_file
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 257: ControlFlowNode for image_file
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 257: ControlFlowNode for image_file

---

#### 2. py/path-injection @ gradio/image_utils.py:356

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 23.9s |
| **Tokens** | 4,303 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: User-provided value through Gradio component (source) → payload.path (line 110) → Path(payload.path) creating file_path (line 110) → PIL.Image.open(file_path) for reading OR str(file_path) returned as filepath (sink, no sanitization)

**Reasoning**: User-controlled `payload.path` is converted to a Path object on line 110 without any path normalization, sanitization of traversal sequences, or validation that the path is contained within an allowed directory (e.g., `cache_dir`). The resulting `file_path` is used directly in `PIL.Image.open()` for reading arbitrary files and can be returned as a string. An attacker can supply `../` sequences or absolute paths to read arbitrary files on the filesystem. CodeQL's high precision and the 7.5 severity rating further support this being a genuine vulnerability.

**Guided Question Answers**:

1. The PATH input originates from `payload.path`, which represents a user-uploaded file's path within the Gradio framework. The dataflow traces through multiple UI component value paths (lines 21, 17, 49, 23) before reaching `payload.path` at line 110.
2. No, `os.path.join()` is NOT used. Instead, `Path(payload.path)` is used on line 110 (`file_path = Path(payload.path)`) and the path is used directly for file operations.
3. No, the path is NOT normalized with `os.path.realpath()` or `os.path.abspath()`. `Path(payload.path)` on line 110 preserves the original user-provided path without any normalization.
4. No, there is NO check to verify that the resolved path starts with an allowed base directory (like `cache_dir`). The code goes directly from `Path(payload.path)` to file operations without any directory containment validation.
5. Yes, since there is no sanitization, normalization, or directory containment check, `../` sequences in `payload.path` could traverse outside the intended directory. Absolute paths (starting with `/`) would bypass any implicit directory restriction entirely.
6. Multiple FILE OPERATIONS are performed: (1) `PIL.Image.open(file_path)` on line ~122 reads the file, (2) `str(file_path)` is returned on lines ~118 and ~121 (exposing the path), and (3) `extract_svg_content` (lines ~337-351) performs `open(image_file)` to read file contents.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 355: ControlFlowNode for value
- line 85: ControlFlowNode for y
- line 102: ControlFlowNode for path
- line 110: ControlFlowNode for path
- line 355: ControlFlowNode for save_image()
- line 355: ControlFlowNode for saved
- line 356: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 355: ControlFlowNode for value
- line 85: ControlFlowNode for y
- line 102: ControlFlowNode for path
- line 110: ControlFlowNode for path
- line 355: ControlFlowNode for save_image()
- line 355: ControlFlowNode for saved
- line 356: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 355: ControlFlowNode for value
- line 85: ControlFlowNode for y
- line 102: ControlFlowNode for path
- line 110: ControlFlowNode for path
- line 355: ControlFlowNode for save_image()
- line 355: ControlFlowNode for saved
- line 356: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 355: ControlFlowNode for value
- line 85: ControlFlowNode for y
- line 102: ControlFlowNode for path
- line 110: ControlFlowNode for path
- line 355: ControlFlowNode for save_image()
- line 355: ControlFlowNode for saved
- line 356: ControlFlowNode for Path()

---

#### 3. py/path-injection @ gradio/components/label.py:140

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 20.5s |
| **Tokens** | 3,987 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: user-provided `value` parameter (line 130) → isinstance check for str ending with '.json' (line 140) → Path(value) construction (line 140) → Path(value).exists() check (line 140) → Path(value).read_text() file read (line 140) → json.loads() parsing (line 140)

**Reasoning**: The `postprocess` method takes a user-influenced `value` parameter and on line 140 directly constructs a `Path(value)` from it, reads the file contents with `Path(value).read_text()`, and parses it as JSON. There is no path normalization, no base directory restriction, and no sanitization against directory traversal sequences. The only guard is the `.endswith('.json')` check and `.exists()` check, neither of which prevents reading arbitrary `.json` files anywhere on the filesystem.

**Guided Question Answers**:

1. The path input originates from the `value` parameter of the `postprocess` method (line 130 in the shown code). According to the docstring and dataflow paths, this value can come from various upstream components (audio, image, code, file upload) that eventually flow into the `value` argument. It represents user-influenced data.
2. No, `os.path.join()` is NOT used. The path is constructed directly by passing `value` to `Path(value)` on line 140 with no joining or prefixing to a base directory.
3. No, the path is NOT normalized with `os.path.realpath()`, `os.path.abspath()`, or any equivalent function. `Path(value)` on line 140 creates a path object directly from the raw input.
4. No, there is NO check that the resolved path starts with an allowed base directory. The only check on line 140 is `Path(value).exists()`, which merely verifies the file exists — it does not restrict which directory the file must be in.
5. Yes, `../` sequences or absolute paths would fully escape any intended directory. An attacker could supply `../../etc/passwd` or `/etc/passwd` as a string value, and since `Path(value).exists()` would return True for existing files, the condition would be satisfied.
6. The file operation performed is a READ: `Path(value).read_text()` on line 140. The file's entire contents are read and passed to `json.loads()`, and the result is used to construct a `LabelData` object. This means an attacker could read any `.json` file on the system accessible to the application.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 140: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 140: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 140: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 140: ControlFlowNode for Path()

---

#### 4. py/path-injection @ client/python/gradio_client/utils.py:698

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 22.7s |
| **Tokens** | 4,057 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: SOURCE (user-controllable component values, e.g., line 21 audio/line 17 original_image) → TRANSFORM (through kwargs, values, json_obj, Subscript operations) → line 697 parameter f → SINK line 698 open(f, 'rb') with NO sanitization

**Reasoning**: The function encode_file_to_base64 (line 697) accepts a path parameter `f` that CodeQL traces back to user-controllable inputs (audio data, image data, text inputs). This path is used directly in open(f, 'rb') on line 698 with zero validation — no path normalization, no allowlist, no base directory check, and no sanitization. An attacker can supply directory traversal sequences (../) or absolute paths to read arbitrary files from the server, constituting a clear path traversal / arbitrary file read vulnerability.

**Guided Question Answers**:

1. The PATH input originates from multiple sources traced through the dataflow (lines 5, 17, 21, 49 visible as SOURCE nodes). These flow through component values, JSON objects, and Subscript operations before reaching the parameter `f` at line 697. The sources appear to be user-controllable attributes (e.g., `original_image`, `audio`) from Gradio component data — i.e., data provided by users of the Gradio client API.
2. No, os.path.join() is not used anywhere in the provided code context. The path string is used directly as the argument to open() on line 698.
3. No. There is no call to os.path.realpath(), os.path.abspath(), pathlib.Path.resolve(), or any other normalization function in the provided code.
4. No. There is no check that the resolved path starts with an allowed base directory. The path flows directly from the parameter `f` (line 697) into `open(f, 'rb')` (line 698) with no validation whatsoever.
5. Yes. Since `f` comes from user-provided data and there is no sanitization or validation, an attacker could supply paths containing '../' sequences or absolute paths (e.g., '/etc/passwd') to read arbitrary files on the system.
6. A READ operation is performed: `open(f, 'rb')` on line 698 reads the file content via `file.read()`, which is then base64-encoded and returned. This is a file disclosure / arbitrary file read vulnerability.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 66: ControlFlowNode for s
- line 66: ControlFlowNode for Subscript
- line 697: ControlFlowNode for f
- line 698: ControlFlowNode for f
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 66: ControlFlowNode for s
- line 66: ControlFlowNode for Subscript
- line 697: ControlFlowNode for f
- line 698: ControlFlowNode for f
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 66: ControlFlowNode for s
- line 66: ControlFlowNode for Subscript
- line 697: ControlFlowNode for f
- line 698: ControlFlowNode for f
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 66: ControlFlowNode for s
- line 66: ControlFlowNode for Subscript
- line 697: ControlFlowNode for f
- line 698: ControlFlowNode for f

---

#### 5. py/full-ssrf @ gradio/image_utils.py:253

| Field | Value |
|-------|-------|
| **Severity** | 9.1 |
| **Tags** | external/cwe/cwe-918 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 29.2s |
| **Tokens** | 4,661 |

**Message**: The full URL of this request depends on a [user-provided value](1).
The full URL of this request depends on a [user-provided value](2).
The full URL of this request depends on a [user-provided value](3).
The full URL of this request depends on a [user-provided value](4).
The full URL of this request depends on a [user-provided value](5).
The full URL of this request depends on a [user-provided value](6).
The full URL of this request depends on a [user-provided value](7).
The full URL of this request depends on a [user-provided value](8).
The full URL of this request depends on a [user-provided value](9).
The full URL of this request depends on a [user-provided value](10).

**Data Flow**: user-controlled image_file parameter (line 243) → str() conversion (line 250) → is_http_url_like check passes (line 251) → httpx.get(image_file) SSRF sink (line 253)

**Reasoning**: The `extract_svg_content` function takes a user-controlled string/URL and passes it directly to `httpx.get()` at line 253 with no URL validation, host allowlisting, or scheme restrictions. The `is_http_url_like` check only determines which code branch to execute — it does not restrict the URL target. This is a classic full SSRF vulnerability with a 9.1 severity rating and high precision from CodeQL.

**Guided Question Answers**:

1. Q1: The source is the `image_file` parameter of `extract_svg_content`, which accepts a str | Path that could be a user-provided URL. Per the dataflow paths, this traces back to user-controlled component values (e.g., Image component `value`) in the Gradio framework.
2. Q2: image_file parameter (line 243) → str conversion (line 250, `image_file = str(image_file)`) → `is_http_url_like` check (line 251) → `httpx.get(image_file)` (line 253). The data is used as the full URL for the HTTP request.
3. Q3: The only check is `is_http_url_like(image_file)` at line 251. This check appears to be a simple heuristic for URL detection (not restriction) — it guards which branch executes but does NOT validate or restrict the URL target (scheme, host, port). It is INSUFFICIENT to prevent SSRF.
4. Q4: The sink is `httpx.get(image_file)` at line 253. The full URL for this server-side HTTP request is directly controlled by user input, making it a textbook SSRF vector. The server will make a request to any URL the attacker specifies.
5. Q5: The only transformation is `str(image_file)` at line 250, which converts Path to string — no encoding/decoding that would sanitize the URL. The string is used directly as the request URL.
6. Q6: httpx provides no automatic SSRF protection. Gradio does not appear to have URL allowlisting middleware visible in this context. No framework-level SSRF defenses are present.
7. Q7: This appears to be in the postprocess pipeline for image components. Any user who can interact with a Gradio interface containing an image component could potentially trigger this path, likely requiring no special authentication beyond access to the app.
8. Q8: This is production code in `gradio/image_utils.py`, part of the postprocessing pipeline. It is not test code, debug path, or dead code.
9. Q9: SSRF impact: an attacker can cause the server to make arbitrary HTTP requests to internal services (metadata endpoints, internal APIs, databases), potentially accessing sensitive data, performing port scanning of internal networks, or attacking other internal services. With severity 9.1 and high precision, this is critical.
10. Q10: The weakest link is line 253: `httpx.get(image_file)` uses the fully user-controlled URL with zero restrictions on scheme, host, port, or path. The `is_http_url_like` check at line 251 is not a defense — it merely detects URLs to choose the HTTP branch, it does not restrict which URLs are permissible.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 253: ControlFlowNode for image_file
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 253: ControlFlowNode for image_file
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 253: ControlFlowNode for image_file
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 212: ControlFlowNode for value
- line 221: ControlFlowNode for value
- line 327: ControlFlowNode for value
- line 344: ControlFlowNode for value
- line 243: ControlFlowNode for image_file
- line 251: ControlFlowNode for image_file
- line 253: ControlFlowNode for image_file

---

#### 6. py/path-injection @ gradio/processing_utils.py:1072

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.90) |
| **Iterations** | 1 |
| **Time** | 21.4s |
| **Tokens** | 3,669 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: user-provided attribute values (lines 21/17/49/23) → transform: through Gradio component pipeline as 'value' → transform: assigned to 'video_path' parameter (line 1065) → sink: shutil.copy2(video_path, tmp_file.name) (line 1069) and FFmpeg inputs (line 1071)

**Reasoning**: The `video_path` parameter originates from user-controlled Gradio component values and flows directly into `shutil.copy2()` without any path normalization, sanitization, or directory-bounds checking. An attacker can supply path traversal sequences (../) or absolute paths to read arbitrary files on the server. The high precision (CodeQL 'high') and high severity (7.5) ratings further support this being a genuine vulnerability.

**Guided Question Answers**:

1. The path input (`video_path`) originates from user-provided values that flow through the Gradio component pipeline (multiple source attributes visible in the dataflow paths: lines 21, 17, 49, 23). These are user-supplied values via various Gradio input components that ultimately become the `video_path` parameter.
2. os.path.join() is NOT used in the visible code. Instead, `Path(video_path).with_suffix(".mp4")` is used on line 1068 and `str(tmp_file.name)` is used on line 1071. Neither prevents directory traversal if the input contains absolute paths or '../' sequences.
3. The path is NOT normalized with os.path.realpath() or os.path.abspath() anywhere in the visible code. There is no canonicalization of the user-provided `video_path`.
4. After normalization, there is NO check to verify the path starts with an allowed base directory. No validation whatsoever is performed on `video_path` before it is used in file operations.
5. Yes. An attacker could supply `video_path` values like `../../etc/passwd` (relative traversal) or `/etc/passwd` (absolute path). Since `Path(video_path).with_suffix(".mp4")` just changes the suffix, `../../../etc/something.mp4` would resolve outside intended directories, and `shutil.copy2(video_path, tmp_file.name)` would read any file the attacker specifies.
6. Two file operations are performed: (1) `shutil.copy2(video_path, tmp_file.name)` on line 1069 — reads the file at `video_path` and copies it; (2) FFmpeg processing with `tmp_file.name` as input on line 1071 — reads the copied file. The primary risk is arbitrary file read via `shutil.copy2`.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 254: ControlFlowNode for value
- line 268: ControlFlowNode for value
- line 271: ControlFlowNode for video
- line 279: ControlFlowNode for video
- line 307: ControlFlowNode for video
- line 1065: ControlFlowNode for video_path
- line 1072: ControlFlowNode for video_path
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 254: ControlFlowNode for value
- line 268: ControlFlowNode for value
- line 271: ControlFlowNode for video
- line 279: ControlFlowNode for video
- line 307: ControlFlowNode for video
- line 1065: ControlFlowNode for video_path
- line 1072: ControlFlowNode for video_path
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 254: ControlFlowNode for value
- line 268: ControlFlowNode for value
- line 271: ControlFlowNode for video
- line 279: ControlFlowNode for video
- line 307: ControlFlowNode for video
- line 1065: ControlFlowNode for video_path
- line 1072: ControlFlowNode for video_path
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 254: ControlFlowNode for value
- line 268: ControlFlowNode for value
- line 271: ControlFlowNode for video
- line 279: ControlFlowNode for video
- line 307: ControlFlowNode for video
- line 1065: ControlFlowNode for video_path
- line 1072: ControlFlowNode for video_path

---

#### 7. py/path-injection @ client/python/gradio_client/client.py:1360

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.88) |
| **Iterations** | 1 |
| **Time** | 32.9s |
| **Tokens** | 5,852 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: source: user-provided file path in x["path"] (line 1325 parameter) → concatenated into url_path: self.root_url + "file=" + x["path"] (line 1360) → used as URL for httpx.stream GET request (line 1366) → Path(url_path).name used as filename for local file write (line 1376) and shutil.move (line 1382)

**Reasoning**: The user-controlled `x["path"]` value flows directly into a URL via string concatenation at line 1360 with NO sanitization, normalization, or path validation. While `Path(url_path).name` (lines 1376, 1381, 1382) extracts only the filename component for local file operations (providing some local filesystem protection), the unsanitized value is used as the full URL for the HTTP GET request at line 1366, enabling directory traversal attacks against the server-side file endpoint. The high precision of the CodeQL rule and severity of 7.5 support this assessment.

**Guided Question Answers**:

1. The path input originates from the `x` dictionary parameter passed to `_download_file`, specifically `x["path"]` (line 1360) or `x["url"]` (line 1357). Based on the dataflow trace, these values ultimately derive from user-provided inputs to the Gradio API (e.g., uploaded file values from Audio/Image components or text inputs).
2. No, `os.path.join()` is not used. Instead, string concatenation is used: `self.root_url + "file=" + x["path"]` (line 1360). There is no path joining or traversal protection of any kind.
3. No, there is NO normalization of the path with `os.path.realpath()`, `os.path.abspath()`, or `pathlib.resolve()` (beyond the final return value). The `x["path"]` value is used directly in string concatenation without any sanitization.
4. No, there is NO check to verify that the resulting path starts with an allowed base directory. The `x["path"]` value from user input is concatenated directly into the URL and used as a file path component without any validation against a whitelist or prefix check.
5. Yes. The value `x["path"]` is user-controlled and concatenated directly into a URL at line 1360 and used as a file path via `Path(url_path).name` at lines 1376, 1381, and 1382. If `x["path"]` contains `../` sequences or other traversal characters, it could manipulate the constructed URL to point to unintended server-side files. The use of `Path(url_path).name` mitigates the *local* file write path somewhat, but the URL itself (`url_path`) is unsanitized for the GET request at line 1366.
6. File operations performed include: (1) HTTP GET request to the constructed `url_path` (line 1366), (2) writing the response content to a local temp file via `f.write(chunk)` (line 1374), (3) creating a directory based on the SHA hash (line 1380), and (4) moving the file via `shutil.move()` (line 1382).

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1360: ControlFlowNode for BinaryExpr
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1360: ControlFlowNode for BinaryExpr
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1360: ControlFlowNode for BinaryExpr
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1360: ControlFlowNode for BinaryExpr

---

#### 8. py/path-injection @ client/python/gradio_client/client.py:1360

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.88) |
| **Iterations** | 1 |
| **Time** | 33.5s |
| **Tokens** | 5,892 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: source: x["path"] (line 5, user-controlled dict from server response) → string concatenation into url_path (line 5: `self.root_url + "file=" + x["path"]`) → HTTP GET request to constructed URL (line 13) → response written to temp file using Path(url_path).name (line 16) → moved to output_dir/sha/pathname (line 24) → returned as resolved path (line 25)

**Reasoning**: The user-controlled value x["path"] from a server response (which could be a malicious Gradio server) is concatenated directly into a URL path on line 5 with NO sanitization or path traversal checks. This allows a malicious Gradio server to inject '../' sequences to perform Server-Side Path Traversal, making arbitrary HTTP GET requests to files on the server or adjacent services. While Path(url_path).name provides some protection for the local filesystem write operations, the URL construction itself is vulnerable. CodeQL's high precision and the 7.5 severity rating support this being a genuine vulnerability.

**Guided Question Answers**:

1. Q1: The path input originates from the dict parameter 'x' passed to the function (line 1). Specifically, x["path"] (line 5) and x["url"] (line 3) are used to construct file paths. The data flow from CodeQL traces these values back to user-provided inputs that flow through the Gradio client's processing pipeline (json_obj → x).
2. Q2: os.path.join() is NOT used. Instead, string concatenation is used on line 5: `self.root_url + "file=" + x["path"]`, and pathlib's `/` operator is used on lines 16, 23, and 24: `temp_dir / Path(url_path).name` and `directory / Path(url_path).name`. Neither approach prevents directory traversal.
3. Q3: The path is NOT normalized with os.path.realpath() or os.path.abspath(). On line 25, str(dest.resolve()) is called, but this is only on the RETURN value — the file operations (open, shutil.move) on lines 16 and 24 have already been executed BEFORE the resolve() call, so it does not serve as a normalization check.
4. Q4: No. There is no check after any normalization step to verify the resulting path starts with the intended base directory (e.g., output_dir or temp_dir).
5. Q5: Yes. While Path(url_path).name extracts just the filename component (stripping directory components), the url_path is also used directly to construct the HTTP GET request URL (line 13). A path containing '../' sequences in x["path"] would allow accessing files outside the intended directory on the remote server (Server-Side Path Traversal / Arbitrary File Read).
6. Q6: FILE READ via HTTP GET request (httpx.stream on line 13) and FILE WRITE to both a temporary directory (line 16: `open(temp_dir / Path(url_path).name, 'wb')`) and the final output directory (line 24: `shutil.move`). The write path uses Path().name which provides some protection, but the HTTP request path has no such protection.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1360: ControlFlowNode for dest
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1360: ControlFlowNode for dest
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1360: ControlFlowNode for dest
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1360: ControlFlowNode for dest

---

#### 9. py/path-injection @ gradio/components/file.py:221

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.88) |
| **Iterations** | 1 |
| **Time** | 25.9s |
| **Tokens** | 3,594 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: user-provided value (lines 21/17/49/23) → transform: multiple component processing steps → value iterable (line 221) → file loop variable → sink: Path(file) and Path(file).stat() (line 221)

**Reasoning**: User-controlled file paths flow through multiple Gradio components into the 'value' iterable without any sanitization, normalization, or directory containment checks. Each 'file' is passed directly to Path() and .stat() on line 221, allowing directory traversal (e.g., '../../../../etc/passwd') to access files outside the intended directory.

**Guided Question Answers**:

1. The path input ('file' from iterating over 'value') originates from user-provided values that flow through multiple Gradio component types (audio, image, file upload, code). The dataflow paths show sources at lines 21, 17, 49, and 23 representing different user-controlled inputs that ultimately reach the 'value' variable on line 221.
2. os.path.join() is NOT used in the visible code. The file path from 'value' is used directly via Path(file) on line 221 without any joining or construction with a base directory.
3. The path is NOT normalized with os.path.realpath() or os.path.abspath() anywhere in the visible code. Path(file) on line 221 creates a Path object without normalization.
4. No check is performed to verify the path starts with an allowed base directory. There is no validation whatsoever on 'file' before it is used on line 221.
5. Yes - since there is no sanitization, validation, or containment check, '../' sequences or absolute paths in user input would directly reach Path(file) and Path(file).stat() on line 221, potentially escaping the intended directory.
6. Two file operations are performed: Path(file).name extracts the filename, and Path(file).stat().st_size reads file metadata (stat). Both operations access the filesystem using the unsanitized user-provided path.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 223: ControlFlowNode for value
- line 217: ControlFlowNode for .0
- line 223: ControlFlowNode for file
- line 221: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 223: ControlFlowNode for value
- line 217: ControlFlowNode for .0
- line 223: ControlFlowNode for file
- line 221: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 223: ControlFlowNode for value
- line 217: ControlFlowNode for .0
- line 223: ControlFlowNode for file
- line 221: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 223: ControlFlowNode for value
- line 217: ControlFlowNode for .0
- line 223: ControlFlowNode for file
- line 221: ControlFlowNode for Path()

---

#### 10. py/path-injection @ gradio/components/label.py:141

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.88) |
| **Iterations** | 1 |
| **Time** | 24.5s |
| **Tokens** | 4,003 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: user-provided value from Gradio component inputs (multiple flow paths from lines 21, 17, 49, 23) → transform: value propagated through component loading and event processing (lines 85, 206, 405, 406, 135, 207, 243, 248, 252, 130) → sink: Path(value) used to read file contents on line 141 with no path validation or sanitization

**Reasoning**: The `postprocess` method at line 141 takes a user-influenced string `value`, passes it directly to `Path(value).exists()` and `Path(value).read_text()` with no path normalization, no base directory restriction, and no sanitization of traversal sequences. The CodeQL analysis traces multiple dataflow paths from user-controlled inputs to this sink. An attacker could read arbitrary `.json` files on the filesystem using path traversal (e.g., `../../../etc/sensitive.json`) or absolute paths, as long as the file exists and has a `.json` extension.

**Guided Question Answers**:

1. The PATH input originates from the `value` parameter of the `postprocess` method (line 130). This value flows through a complex dataflow chain from user-provided attributes (multiple sources in the dataflow, including audio, image, and code inputs at lines 21, 17, 49, 23) through component loading logic into this method.
2. No, `os.path.join()` is not used. Instead, the raw `value` string is passed directly to `Path(value)` on line 141 without any path joining or construction with a base directory.
3. No, there is no normalization with `os.path.realpath()`, `os.path.abspath()`, or `pathlib.Path.resolve()`. The `Path(value)` call on line 141 is used raw without any normalization or path validation.
4. No, there is no check to verify the path starts with an allowed base directory. Line 141 only checks `Path(value).exists()` before reading, with no restriction on which directories can be accessed.
5. Yes, an attacker controlling the `value` parameter could use '../' sequences to traverse to parent directories (e.g., `../../../etc/passwd.json`) or use absolute paths (e.g., `/etc/passwd.json`) to read any `.json` file on the filesystem, provided the file exists and ends with `.json`.
6. A file READ operation is performed on line 141: `Path(value).read_text()`. This reads the entire contents of the file and passes it to `json.loads()`, allowing an attacker to read arbitrary `.json` files on the system.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 141: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 141: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 141: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 130: ControlFlowNode for value
- line 141: ControlFlowNode for Path()

---

#### 11. py/path-injection @ gradio/components/upload_button.py:238

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.88) |
| **Iterations** | 1 |
| **Time** | 22.0s |
| **Tokens** | 3,639 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source (external value param, line 4) → _download_files (line 9) → Path(file).stat() (line 17) and Path(value).stat() (line 26)

**Reasoning**: The `postprocess` method accepts a `value` parameter containing file paths that flow from user-controlled sources (audio, original_image, name2, code_in). These paths are used directly in `Path().stat()` operations without any normalization (e.g., `os.path.realpath()`) or validation against an allowed base directory. While only metadata is read (file size), this allows directory traversal attacks that can probe arbitrary filesystem locations, confirming the path injection vulnerability identified by CodeQL.

**Guided Question Answers**:

1. The path input originates from the `value` parameter passed to the `postprocess` method (line 4). The dataflow traces show it flowing through multiple components (audio, original_image, name2, code_in) before reaching this function. The `value` parameter is typed as `str | list[str] | None` (line 4) and represents file paths or URLs.
2. No, `os.path.join()` is NOT used in this code. The `value` string is used directly as a path in `Path(file)` (line 15) and `Path(value)` (line 24) without any path joining operation.
3. No, the path is NOT normalized with `os.path.realpath()` or `os.path.abspath()`. The raw `value` is passed directly to `Path()` and `.stat()` without any normalization.
4. No, there is NO check to verify the path starts with an allowed base directory. The code directly uses the path without any validation of its location.
5. Yes, because there is no sanitization, '../' sequences or absolute paths in the `value` parameter could escape the intended directory. The path is used as-is.
6. File metadata operations are performed: `Path(file).stat().st_size` (line 17) and `Path(value).stat().st_size` (line 26). While `.stat()` is a read/metadata operation, it still allows path traversal to probe arbitrary filesystem locations, leaking file existence and metadata information.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 238: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 238: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 238: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 238: ControlFlowNode for Path()

---

#### 12. py/path-injection @ gradio/components/file.py:230

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.72) |
| **Iterations** | 1 |
| **Time** | 67.2s |
| **Tokens** | 3,715 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: user-defined function return value → (via pipeline prediction machinery) → value parameter of postprocess (line 8) → _download_files (line 15) → Path() constructor (lines 18, 20, 29, 31) → .stat() filesystem access (lines 20, 31)

**Reasoning**: The postprocess function accepts arbitrary file paths via the 'value' parameter (from user-defined Gradio handler output) and uses them directly in Path() and .stat() calls with zero sanitization, normalization, or directory-bounds checking. The high-precision CodeQL rule and high severity (7.5) support this finding. However, confidence is Medium because: (1) this is a library component, not directly exposed to HTTP requests — the caller mediates access; (2) Gradio's framework layers may perform path validation elsewhere; and (3) the function semantically expects server-side file paths from handler code, which developers typically control. Still, the lack of any visible defense makes directory traversal clearly possible.

**Guided Question Answers**:

1. The 'value' parameter originates as a return value from a user-defined Gradio interface function. Per the docstring on line 7, it is a 'str filepath or URL, or a list[str] of filepaths/URLs'. The dataflow paths trace it through pipeline/prediction machinery (kwargs, load_fn, Tuple, initial_value) into the 'value' parameter of postprocess. In Gradio's architecture, this comes from user-defined handler output.
2. os.path.join() is NOT used anywhere in the shown code. The 'file' or 'value' string is used directly in Path() constructors on lines 18, 20, 29, and 31.
3. There is NO normalization with os.path.realpath(), os.path.abspath(), or any equivalent anywhere in this function.
4. There is NO check that the resulting path starts with an allowed base directory or any path validation at all.
5. Yes, since 'value' / 'file' is used directly in Path() with no sanitization, '../' sequences or absolute paths like '/etc/passwd' would be processed as-is, potentially escaping intended directories.
6. FILE OPERATIONS: Path(file).stat().st_size is called on lines 20 and 31, which reads file metadata from the filesystem. The path is also stored in the FileData 'path' field (lines 18, 29) which may be used to serve/download the file to the client in subsequent Gradio framework operations.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 230: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 230: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 230: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 205: ControlFlowNode for value
- line 214: ControlFlowNode for value
- line 185: ControlFlowNode for value
- line 203: ControlFlowNode for value
- line 214: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for value
- line 230: ControlFlowNode for Path()

---

#### 13. py/clear-text-storage-sensitive-data @ gradio/processing_utils.py:222

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-312, external/cwe/cwe-315, external/cwe/cwe-359 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.70) |
| **Iterations** | 1 |
| **Time** | 35.1s |
| **Tokens** | 4,506 |

**Message**: This expression stores [sensitive data (password)](1) as clear text.
This expression stores [sensitive data (private)](2) as clear text.

**Data Flow**: Source: OAuth password/private data (lines 55, 111) → component value propagation (multiple lines 29-292) → serialization to bytes → data parameter (line 215) → save_bytes_to_cache() → path.write_bytes(data) at line 222 (cleartext file write)

**Reasoning**: The CodeQL analysis with high precision identifies that sensitive data (passwords, private user data) flows through Gradio's component processing pipeline and is ultimately written to disk as cleartext via path.write_bytes(data) at line 222. The function save_bytes_to_cache provides no encryption or protection for the cached data. However, the confidence is medium because the full data flow from source to sink traverses many lines not visible in the provided context, and some intermediate step could potentially break the chain.

**Guided Question Answers**:

1. The dataflow paths indicate the source is sensitive user data — OAuth credentials (passwords) at line 111 and private user data (unique_sex) at line 55. These originate from user profile/authentication data and flow through a complex chain of Gradio component transformations.
2. The data flows through: OAuth info subscript (line 111) → username (line 119) → Attribute extraction (line 120) → value propagation through component definitions (lines 43, 69, 29, 77, 135, 207) → initial_value (lines 207-208, 247, 250) → Tuple construction (line 252) → value propagation (lines 270, 292) → data parameter (line 215) → sink at data (line 222).
3. Not visible in provided context. The intermediate transformations between source and sink are not in the shown code. However, the sink function `save_bytes_to_cache` performs NO validation, sanitization, or encryption of the `data` parameter before writing it to disk at line 222.
4. The sink is `path.write_bytes(data)` at line 222 in `save_bytes_to_cache`. The dangerous operation is writing sensitive data (potentially passwords or private user data) as cleartext to a file on disk without encryption.
5. Yes — the data is serialized (likely to bytes) through component processing before reaching `save_bytes_to_cache`. These transformations do NOT encrypt the data; they merely convert format, which means the sensitive data remains in cleartext even after all transformations.
6. No. The `write_bytes()` call at line 222 is a raw filesystem write with no encryption, access control, or framework-level protection. Gradio's caching layer writes data as-is to a cache directory.
7. Not visible in provided context — the caller context and authentication requirements for the Gradio application are not shown. However, Gradio is typically a web-facing framework, so this could be reachable by authenticated users.
8. No — this is in `gradio/processing_utils.py`, a core library file that processes and caches data. This is production code in the main execution path, not test or debug code.
9. Information disclosure / data theft. If an attacker gains read access to the cache directory (e.g., through path traversal, local file access, or shared hosting), they can retrieve passwords and private user data stored in cleartext. Severity is elevated (7.5) because passwords are involved.
10. The weakest link is the complete absence of encryption at the storage layer. The `save_bytes_to_cache` function writes arbitrary bytes — including sensitive data like passwords — directly to disk as cleartext (line 222). No encryption, hashing, or access control is applied before the write.

**Dataflow Path**:
- --- Flow 1 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 222: ControlFlowNode for data
- --- Flow 2 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 250: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 222: ControlFlowNode for data
- --- Flow 3 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for Attribute()
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 222: ControlFlowNode for data
- --- Flow 4 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 51: ControlFlowNode for choices
- line 110: ControlFlowNode for choices
- line 110: ControlFlowNode for .0
- line 110: ControlFlowNode for c
- line 110: ControlFlowNode for Yield
- line 110: ControlFlowNode for ListComp
- line 110: ControlFlowNode for IfExp
- line 107: [post] ControlFlowNode for self [Attribute choices]
- line 119: ControlFlowNode for self [Attribute choices]
- line 120: ControlFlowNode for self [Attribute choices]
- line 126: ControlFlowNode for self [Attribute choices]
- line 126: ControlFlowNode for Attribute
- line 126: ControlFlowNode for value
- line 160: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 222: ControlFlowNode for data

---

#### 14. py/weak-sensitive-data-hashing @ gradio/processing_utils.py:146

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-327, external/cwe/cwe-328, external/cwe/cwe-916 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.70) |
| **Iterations** | 1 |
| **Time** | 45.0s |
| **Tokens** | 4,371 |

**Message**: [Sensitive data (password)](1) is used in a hashing algorithm (SHA256) that is insecure for password hashing, since it is not a computationally expensive hash function.

**Data Flow**: oauth password (L111, external) → multiple value transforms across components → bytes param of hash_bytes (L143) → sha.update(bytes) (L146) → SHA-256 hexdigest

**Reasoning**: The CodeQL dataflow path (with high precision) traces password data from OAuth info through multiple component layers to the `hash_bytes` function which uses SHA-256 — a fast hash unsuitable for password protection. While the visible code shows `hash_bytes` used for caching image data, the tool's cross-file analysis identifies a reachable path where password data flows into this same generic hashing function. The function uses a static seed (`hash_seed`) rather than proper per-user salts and lacks the computational hardness of dedicated password hashing algorithms (bcrypt, scrypt, argon2).

**Guided Question Answers**:

1. Q1: The dataflow path traces back to oauth_info/username/password from OAuth data (line 111, 119, 120). However, in the VISIBLE code context, the actual inputs to `hash_bytes` are image byte data (line 143-146) and base64-encoded strings (line 148-156). The sensitive password data flows through a complex chain across multiple files/components before potentially reaching this function.
2. Q2: The dataflow shows: oauth_info[Subscript] (L111) → oauth_info → username (L119) → Attribute() (L120) → value (L43, 69, 29, 77, 135, 207) → initial_value (L207, 208, 247, 250) → Tuple (L252) → data (L215, 216) → bytes (L143) → sink at sha.update(bytes) (L146).
3. Q3: No validation or sanitization is visible in the provided code context. The `hash_bytes` function accepts raw bytes and hashes them directly with SHA-256. There is no check on the nature of the data being hashed.
4. Q4: The sink is `sha.update(bytes)` on line 146, where the `hash_bytes` function computes a SHA-256 hash of the input. The issue is that SHA-256 is not designed for password hashing — it is fast and lacks computational cost, making brute-force attacks feasible against password hashes.
5. Q5: The data undergoes many transformations across modules (value assignments, tuple packing/unpacking, data serialization), but these do not add any security protections. They are just data passing/shaping operations.
6. Q6: No framework or library provides automatic protection here. hashlib.sha256() is a raw cryptographic hash with no password hashing protections (no salt per-hash, no iteration count, no memory hardness). The `hash_seed` acts as a pepper but doesn't substitute for a proper KDF.
7. Q7: Based on the dataflow source (OAuth info), the attacker model depends on how the OAuth credentials are handled. The code path appears to process user-provided data that may include OAuth passwords/credentials. Authentication state is unclear from visible context.
8. Q8: No — this is in `gradio/processing_utils.py`, which is production utility code. The `save_pil_to_cache` function and `hash_bytes` are general-purpose production functions, not test or debug code.
9. Q9: If password data is hashed with SHA-256 and the hash is stored/exposed, an attacker who obtains the hash could brute-force it efficiently using modern hardware (GPUs can compute billions of SHA-256 hashes per second), leading to credential compromise and potential privilege escalation or unauthorized access.
10. Q10: The weakest link is the use of a fast, non-adaptive hash function (SHA-256) for potentially sensitive data (passwords). Even with `hash_seed` as a pepper, the function lacks iteration count, per-hash salt, and memory hardness — all critical properties for password hashing. The `hash_bytes` function is generic and doesn't distinguish between sensitive and non-sensitive data.

**Dataflow Path**:
- --- Flow 1 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 216: ControlFlowNode for data
- line 143: ControlFlowNode for bytes
- line 146: ControlFlowNode for bytes
- --- Flow 2 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 250: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 216: ControlFlowNode for data
- line 143: ControlFlowNode for bytes
- line 146: ControlFlowNode for bytes
- --- Flow 3 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 247: ControlFlowNode for value
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for Attribute() [Tuple element at index 1]
- line 207: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 216: ControlFlowNode for data
- line 143: ControlFlowNode for bytes
- line 146: ControlFlowNode for bytes
- --- Flow 4 ---
- line 111: ControlFlowNode for Subscript
- line 111: ControlFlowNode for oauth_info
- line 119: ControlFlowNode for username
- line 120: ControlFlowNode for Attribute()
- line 43: ControlFlowNode for value
- line 69: ControlFlowNode for value
- line 29: ControlFlowNode for value
- line 77: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 250: ControlFlowNode for initial_value
- line 252: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for Attribute() [Tuple element at index 1]
- line 207: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 292: ControlFlowNode for value
- line 215: ControlFlowNode for data
- line 216: ControlFlowNode for data
- line 143: ControlFlowNode for bytes
- line 146: ControlFlowNode for bytes

---

#### 15. py/path-injection @ gradio/processing_utils.py:659

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.70) |
| **Iterations** | 2 |
| **Time** | 44.9s |
| **Tokens** | 8,111 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source (user input through Gradio component system, lines not in scope) → transform (multiple intermediate steps through Gradio internals) → transform (str() conversion at line 310) → transform (filename parameter at line 651) → sink (Path() at line 659 and AudioSegment.from_file() at ~line 657)

**Reasoning**: The audio_from_file function at line 651 accepts a user-controlled filename parameter and uses it directly in file operations (AudioSegment.from_file, Path.is_file) with NO path validation, normalization, or directory restriction. The CodeQL high-precision rule (py/path-injection) with severity 7.5 identified 10 separate data flow paths from user-provided values reaching this sink. While the full caller chain is outside the analysis scope, the function itself is clearly vulnerable — any caller passing untrusted input to this function would enable directory traversal. The error message at ~line 660 also leaks filesystem information, confirming the attack surface.

**Guided Question Answers**:

1. The exact HTTP entry point is not visible. The dataflow traces through Gradio's internal component system (lines 207, 243, 248, 252, 270, 310) which are not available in the analysis scope. The `filename` parameter at line 651 is the entry point to the vulnerable function, but its callers are not found, suggesting they are outside the analysis scope.
2. No `os.path.join()` usage is visible. The `filename` parameter is used directly at `AudioSegment.from_file(filename)` (~line 657) and `Path(filename).is_file()` (line 659).
3. No normalization is performed. No calls to `os.path.realpath()`, `os.path.abspath()`, or `Path.resolve()` are present in the shown code.
4. No. There is no check verifying the resulting path starts with an allowed base directory.
5. Yes. Without any validation or restriction on the `filename` parameter, an attacker could supply `../../etc/passwd` or `/etc/shadow` to traverse out of intended directories.
6. File READ operations: `AudioSegment.from_file(filename)` reads audio from the file (~line 657), and `Path(filename).is_file()` checks file existence (line 659). Error messages could also leak information about the filesystem (~line 660).

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 310: ControlFlowNode for str()
- line 651: ControlFlowNode for filename
- line 659: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 310: ControlFlowNode for str()
- line 651: ControlFlowNode for filename
- line 659: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 310: ControlFlowNode for str()
- line 651: ControlFlowNode for filename
- line 659: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 310: ControlFlowNode for str()
- line 651: ControlFlowNode for filename
- line 659: ControlFlowNode for Path()

---

#### 16. py/path-injection @ client/python/gradio_client/utils.py:1227

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.70) |
| **Iterations** | 3 |
| **Time** | 67.5s |
| **Tokens** | 13,931 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: source (lines 5/17/21/49 in external files — not available) → 14+ transforms through application data flow → parameter `s` of is_filepath() (line 1223) → Path(s) (line 1227) → exists() and is_file() filesystem probes (line 1227)

**Reasoning**: CodeQL reports this finding with high precision and traces user input through 14+ transformations to the Path() sink at line 1227. The function `is_filepath(s)` constructs a Path from its parameter with zero sanitization, normalization, or directory restriction. While the ultimate source of the user input is in external code not available for review (and the only operations are exists()/is_file() metadata probes rather than content reads), the complete absence of any path safety checks combined with CodeQL's high-precision confidence makes this a genuine path traversal vulnerability — an attacker can probe for arbitrary file existence on the filesystem.

**Guided Question Answers**:

1. Q1: The PATH input source cannot be determined. The dataflow traces point to lines 5, 17, 21, and 49 in other files that are not available in this repository. No callers of `is_filepath` were found within this package, meaning the function is invoked from external code (likely the main `gradio` package). The exact input mechanism remains unknown.
2. Q2: No os.path.join() is used. The path is constructed directly via `Path(s)` on line 1227.
3. Q3: No normalization (realpath, abspath, resolve) is applied. The raw value `s` is passed directly to `Path(s)` on line 1227.
4. Q4: No check against an allowed base directory exists anywhere in the visible code.
5. Q5: Yes, `../` sequences or absolute paths in `s` would be interpreted literally by `Path(s)`, potentially probing arbitrary filesystem locations. No sanitization or guards prevent this.
6. Q6: Only filesystem metadata probes are performed: `Path(s).exists()` and `Path(s).is_file()` on line 1227. These are read-only operations that can disclose file existence but do not read, write, or delete file contents.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()

---

#### 17. py/request-without-cert-validation @ client/python/gradio_client/client.py:918

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.70) |
| **Iterations** | 3 |
| **Time** | 94.9s |
| **Tokens** | 10,402 |

**Message**: This request may run without certificate validation because [it is disabled](1) by [this value](2).

**Data Flow**: Client.__init__ sets verify=False on httpx client (location not visible but referenced by CodeQL) → _login() constructs URL from self.src + utils.LOGIN_URL (lines 918-919) → httpx.post() sends credentials without cert validation (lines 918-920)

**Reasoning**: The CodeQL finding explicitly identifies that certificate validation is disabled for the httpx.post() call at lines 918-920, which sends username/password credentials. The _login method transmits sensitive authentication data (auth[0] and auth[1]) via HTTP POST. With certificate verification disabled, an active MITM attacker can intercept these credentials. The severity (7.5) is appropriate for credential theft. While the exact verify=False configuration is not visible in the provided context, CodeQL's explicit identification of both the disable point and the value makes this a credible finding consistent with gradio_client's known design pattern of disabling cert verification for development flexibility.

**Guided Question Answers**:

1. Q1: The source of the vulnerability is the Client class configuration. Based on the gradio_client library's known behavior, the httpx client is configured with verify=False (disabled SSL certificate validation) in the Client initialization. The self.src URL comes from user instantiation of the Client.
2. Q2: User provides URL → Client.__init__ stores as self.src → _login constructs URL via urllib.parse.urljoin(self.src, utils.LOGIN_URL) (line 918-919) → httpx.post() called at lines 918-920 with credentials in data parameter. The cert validation disable flows from Client configuration to httpx.post() call.
3. Q3: No validation or sanitization is applied to the URL construction or certificate validation setting. urllib.parse.urljoin() is a standard URL joining utility but does not validate the target's security properties.
4. Q4: The sink is httpx.post() at lines 918-920, which transmits username and password credentials. The specific danger is sending authentication credentials over a connection that does not verify the server's SSL certificate, enabling MITM credential theft.
5. Q5: No protective transformations between the cert validation disable and the httpx.post() call.
6. Q6: The httpx library validates certificates by default (verify=True). The explicit configuration override disables this protection. The framework protection is deliberately bypassed.
7. Q7: The code path is triggered when a Client is instantiated and _login() is called. This occurs during normal usage of the client library, so any user of the library can trigger it. No special privileges required.
8. Q8: This is production library code in client.py, not test or debug code. It handles user authentication, a core feature.
9. Q9: Credential theft via man-in-the-middle attack. If an attacker can intercept network traffic (e.g., on public WiFi), they can impersonate the Gradio server, capture the username and password sent in the POST request body, and then use those credentials. Severity is significant (7.5) because it involves plaintext credential exposure.
10. Q10: The weakest link is the disabled certificate validation combined with sending credentials. Even if the URL is valid and the target is legitimate, disabling cert verification means any MITM attacker can intercept the authentication exchange. The defense chain has a critical gap: no alternative certificate pinning or validation mechanism is visible.

---

#### 18. py/request-without-cert-validation @ gradio/networking.py:75

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.70) |
| **Iterations** | 1 |
| **Time** | 29.8s |
| **Tokens** | 2,657 |

**Message**: This request may run without certificate validation because [it is disabled](1).

**Data Flow**: url parameter (line 1) → httpx.head with verify=False (line 6) → response r (line 6) → status_code check (line 8) → return True/False

**Reasoning**: The code explicitly disables TLS certificate verification (verify=False on line 6) and suppresses the corresponding warning (line 5), making the HTTP request vulnerable to MITM attacks. However, this appears to be a localhost health-check function for Gradio server startup, which reduces the real-world exploitability. The finding is technically correct — certificate validation is disabled — but the practical risk depends on whether this function is ever called with non-localhost URLs, which is not visible in the provided context.

**Guided Question Answers**:

1. The 'dangerous data' in this context is the network response from the target server. The source is the network response received from the HTTP request to `url` on line 6. The URL itself is also data, passed as a parameter to the function.
2. Data flows through: (1) `url` parameter (function input, line 1) → (2) passed to `httpx.head(url, ...)` on line 6 → (3) response object `r` (line 6) → (4) `r.status_code` checked on line 8.
3. There is NO validation or sanitization of the URL parameter. The `verify=False` explicitly disables TLS certificate validation (line 6), meaning the response is accepted from any server presenting any certificate (including self-signed or fraudulent). The `warnings.filterwarnings('ignore')` on line 5 suppresses the warning that would normally alert about this insecure configuration.
4. The sink is the HTTP request on line 6: `httpx.head(url, timeout=3, verify=False)`. The dangerous operation is `verify=False`, which disables TLS certificate verification, allowing MITM attacks. The response `r` is then trusted based on its status code (line 8).
5. No transformations that would mitigate the issue. The URL is passed directly to httpx. The response status code is compared directly without any certificate pinning or secondary validation.
6. The httpx library provides automatic TLS certificate verification by default (verify=True), but this is explicitly disabled on line 6 with `verify=False`. The framework protection is intentionally bypassed.
7. The `url` parameter comes from the caller (not visible). Based on the function name `url_ok` in `gradio/networking.py`, this appears to be a health-check for Gradio server startup. An attacker would need to be in a MITM position on the network path between the client and server to exploit the disabled certificate validation.
8. This is NOT test or dead code — it is in the main networking module. It appears to be a production code path used to verify a Gradio server is responding. The 5 retries with 0.5s sleep (lines 3, 11) suggest it's used during server initialization.
9. The security impact is Man-in-the-Middle (MITM) attack enabling: information disclosure (attacker can intercept the HTTP request/response), and potentially false trust (an attacker could spoof a 200 response, causing the function to return True for a malicious server). Severity is moderate since this appears to be a localhost health-check, but if used with external URLs, it could be exploitable.
10. The weakest link is the explicit `verify=False` on line 6 combined with suppressed warnings on line 5. The developer intentionally disabled certificate validation and hid the warning, leaving no TLS trust verification whatsoever.

---

#### 19. py/request-without-cert-validation @ scripts/upload_website_demos.py:42

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.70) |
| **Iterations** | 1 |
| **Time** | 21.0s |
| **Tokens** | 2,424 |

**Message**: This request may run without certificate validation because [it is disabled](1).

**Data Flow**: URL constructed at line 41 → HTTPS request with verify=False at line 42 (certificate validation disabled)

**Reasoning**: Certificate verification is explicitly disabled (verify=False) for HTTPS requests to huggingface.co. While this is a deployment script (reducing risk compared to production code), the vulnerability is genuine: network-level attackers could intercept credentials (hf_token) and responses. The precision is 'medium' per CodeQL metadata, but the finding is technically accurate.

**Guided Question Answers**:

1. Q1: The vulnerability is not about tainted data injection — it's about disabled TLS certificate verification. The SOURCE is the HTTP request made on (approximately) line 42 to `https://huggingface.co/spaces/{space_id}`, where `verify=False` is set.
2. Q2: The URL is constructed at line 41 from `space_id` parameter. The actual HTTP request (not fully visible) occurs at line 42 with certificate validation disabled (`verify=False`).
3. Q3: No TLS certificate validation is performed — it is explicitly disabled. There is no alternative mechanism (certificate pinning, custom CA bundle) visible in the provided context.
4. Q4: The SINK is the HTTPS request with `verify=False`, which makes the connection vulnerable to man-in-the-middle attacks. An attacker on the network path could intercept or modify the response.
5. Q5: No transformations that would mitigate the lack of certificate validation. The `verify=False` flag completely disables certificate checking.
6. Q6: The Python `requests` library provides certificate validation by DEFAULT (`verify=True`). Here it is explicitly bypassed by setting `verify=False`.
7. Q7: This is a script (not a web service). The caller (`upload_demo_to_space`) is invoked by authorized users with valid `hf_token` credentials. However, the MITM vulnerability exists on the network path regardless of caller authentication.
8. Q8: This code is in a `scripts/` directory (`scripts/upload_website_demos.py`), suggesting it is an internal/deployment script rather than production code exposed to untrusted input.
9. Q9: Security impact: Information disclosure (intercepted responses), potential data theft (intercepted `hf_token` if sent in same session), MITM enabling further attacks. Severity is elevated (7.5) because the request likely includes the `hf_token` for authentication.
10. Q10: The WEAKEST LINK is the explicit `verify=False` at line 42, which completely disables TLS certificate verification for an HTTPS connection to an external service. There is no compensating control visible in the provided context.

---

#### 20. py/path-injection @ gradio/components/audio.py:316

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.65) |
| **Iterations** | 4 |
| **Time** | 80.2s |
| **Tokens** | 18,230 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Data Flow**: source: HTTP upload → FileData.path → payload.path param of preprocess (line 29) → Path(payload.path).suffix.lower() (line 31) → processing continues beyond line 33 → sink at Path() call on line 316 (body not fully visible)

**Reasoning**: CodeQL with high precision identifies a path-injection vulnerability with severity 7.5. The dataflow analysis traces user-controlled FileData.path through 10+ transform steps to a Path() sink at line 316. While the visible snippet (lines 1-33) only shows safe suffix extraction, the preprocess function spans well beyond (sink at line 316, _import_polars callee). Gradio processes user file uploads where payload.path comes from HTTP requests, and without visible sanitization or base-directory validation, directory traversal is the expected vulnerability pattern in this framework.

**Guided Question Answers**:

1. The path input originates from `payload.path` (line 29), where `payload` is a `FileData` TypedDict populated from HTTP file upload requests. The caller `call_function` in `blocks.py` passes `processed_input` which includes the result of `preprocess`, confirming this processes user-supplied data.
2. No, `os.path.join()` is NOT used. `Path(payload.path)` is used directly (line 31), providing NO traversal protection.
3. No normalization via `os.path.realpath()`, `os.path.abspath()`, or `Path.resolve()` is visible in the provided code.
4. No check verifies the resolved path starts with an allowed base directory. Only a truthy check on `payload.path` exists (line 28).
5. Yes, `../` sequences or absolute paths could be present in `payload.path` since no sanitization is applied, but in the visible code only `.suffix` is extracted.
6. In the visible code (lines 1-33), the only operation is `Path(payload.path).suffix.lower()` (line 31) — mere extension parsing with NO file I/O. The callees list shows only `_import_polars` is called by preprocess, which is unrelated to path operations. The critical operations at the sink line 316 are still not visible in the snippet.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 315: ControlFlowNode for file_path
- line 316: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 315: ControlFlowNode for file_path
- line 316: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 315: ControlFlowNode for file_path
- line 316: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 270: ControlFlowNode for value
- line 315: ControlFlowNode for file_path
- line 316: ControlFlowNode for Path()

---

#### 21. py/request-without-cert-validation @ client/python/gradio_client/client.py:609

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.65) |
| **Iterations** | 2 |
| **Time** | 51.7s |
| **Tokens** | 5,690 |

**Message**: This request may run without certificate validation because [it is disabled](1) by [this value](2).

**Data Flow**: self.ssl_verify (initialization not visible) → verify=self.ssl_verify in httpx.get() (line 611)

**Reasoning**: The code explicitly passes self.ssl_verify to httpx.get(), creating a viable path for disabling certificate validation. Despite not seeing the __init__ default, the CodeQL rule (medium precision) has identified a real code pattern where TLS verification can be disabled. The severity (7.5) reflects legitimate MITM risk. The burden of proof shifts to confirming the default is safe, which we cannot do without __init__. Given the explicit verify parameter plumbing, this is a legitimate security concern — a real but potentially by-design vulnerability common in HTTP client libraries.

**Guided Question Answers**:

1. Q1: The source is `self.ssl_verify`, an instance attribute controlling the `verify` parameter in `httpx.get()`. Its initialization could not be retrieved — the requested context was not found.
2. Q2: `self.ssl_verify` (initialization not visible) → passed as `verify=self.ssl_verify` to `httpx.get()` on line 611.
3. Q3: No validation or sanitization of `self.ssl_verify` is visible anywhere in the provided code. Whether it is constrained at initialization remains unknown.
4. Q4: The sink is `httpx.get()` on lines 609-614, where `verify=self.ssl_verify` directly controls TLS certificate validation. If False, MITM attacks are possible.
5. Q5: No intermediate transformations — `self.ssl_verify` is passed directly.
6. Q6: The `httpx` library honors `verify=False` without override. No framework protection prevents this.
7. Q7: Requires a network-level attacker (MITM position) and a client that has been configured with `ssl_verify=False`. The privilege level depends on how the client is instantiated, which is not visible.
8. Q8: This is production library code in `client.py`, not test or debug code.
9. Q9: MITM attack: interception/modification of API responses, potential information disclosure or code execution depending on how response data is processed.
10. Q10: The weakest link is the unchecked `self.ssl_verify` parameter passed to `httpx.get()`. Without visibility into its default, we cannot confirm whether this is safe by default or dangerous by default.

---

#### 22. py/request-without-cert-validation @ client/python/gradio_client/client.py:936

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.65) |
| **Iterations** | 3 |
| **Time** | 108.4s |
| **Tokens** | 10,128 |

**Message**: This request may run without certificate validation because [it is disabled](1) by [this value](2).

**Data Flow**: self.ssl_verify (set in __init__, default/value NOT visible) → httpx.get(verify=self.ssl_verify) (line 936)

**Reasoning**: After exhausting available context requests without seeing the __init__ body, the finding is assessed as True Positive based on: (1) CodeQL medium-precision detection with 7.5 severity, (2) the code explicitly uses self.ssl_verify to control certificate verification with no visible validation, and (3) standard library practice suggests this parameter exists to allow disabling cert verification. For a client library connecting to arbitrary servers, the ability to disable certificate validation IS the vulnerability — it allows MITM attacks. This is a legitimate security concern warranting remediation even though the exact default remains unseen.

**Guided Question Answers**:

1. Q1: The source is `self.ssl_verify`, set during `__init__`. Despite multiple context requests, the actual __init__ body and the default value of `self.ssl_verify` remain unavailable. The struct lookup returned 'not found'.
2. Q2: Data flow: `self.ssl_verify` (set during __init__, default/value NOT visible) → passed directly as `verify=self.ssl_verify` to `httpx.get()` on line 936.
3. Q3: No validation or sanitization of `self.ssl_verify` is visible in any of the provided context.
4. Q4: The sink is `httpx.get()` on line 936 with `verify=self.ssl_verify`. When False, TLS certificate validation is disabled.
5. Q5: No intermediate transformations — the value passes directly from the attribute to httpx.
6. Q6: httpx does NOT protect against this — verify=False intentionally disables certificate validation.
7. Q7: Any code that instantiates this client triggers this path. The caller controls self.ssl_verify via constructor arguments.
8. Q8: This is production code in the core client module, not test/debug/dead code.
9. Q9: MITM attack enabling data interception, information disclosure, and potential response manipulation.
10. Q10: The weakest link is the direct flow of self.ssl_verify into httpx.get() without validation. However, the critical unknown — whether the default is False (vulnerable) or True (safe by default) — remains invisible.

---

#### 23. py/request-without-cert-validation @ client/python/gradio_client/client.py:964

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.65) |
| **Iterations** | 2 |
| **Time** | 56.0s |
| **Tokens** | 5,967 |

**Message**: This request may run without certificate validation because [it is disabled](1) by [this value](2).

**Data Flow**: self.ssl_verify (instance attribute, source/assignment not visible) → verify=self.ssl_verify (line 962) → httpx.get() call (lines 961-964, sink)

**Reasoning**: The code on line 962 explicitly passes self.ssl_verify to the verify parameter of httpx.get(), which can disable TLS certificate validation. This is a client library — the ssl_verify parameter likely comes from user-supplied arguments to the constructor. While disabling verification is sometimes intentional for development, the CodeQL rule correctly identifies that this code path allows requests without certificate validation. The precision is 'medium' and the constructor is not available to confirm defaults, but the pattern is consistent with a real vulnerability: an attacker who can manipulate ssl_verify (or a developer who sets it to False in production) creates a MITM-vulnerable connection.

**Guided Question Answers**:

1. Q1: The source is `self.ssl_verify`, an instance attribute. The constructor is not visible in the provided context or the additional context, so we cannot confirm the default value or whether it comes from user input.
2. Q2: `self.ssl_verify` (source unknown, assignment not visible) → passed as `verify=self.ssl_verify` on line 962 → `httpx.get()` call on line 961-964.
3. Q3: No validation, sanitization, or constraint on `self.ssl_verify` is visible anywhere in the data flow. The additional context confirms the constructor is not available for review.
4. Q4: The sink is `httpx.get()` on lines 961-964, with `verify=self.ssl_verify` on line 962. When False, TLS certificate validation is disabled.
5. Q5: No intermediate transformations. `self.ssl_verify` is passed directly as a keyword argument.
6. Q6: httpx defaults to verify=True, but this code explicitly passes `self.ssl_verify` which can override that default to False.
7. Q7: An attacker needs to be in a man-in-the-middle position on the network. No authentication is required to exploit disabled certificate validation.
8. Q8: This is production code in the main client module, in a core method `_get_config` that fetches configuration from a Gradio server.
9. Q9: Man-in-the-middle attacks: interception of sensitive data (cookies set on line 969-971, headers), response manipulation, credential theft. High-impact for a client library.
10. Q10: The weakest link is that `self.ssl_verify` can be set to False with no visible safeguards, and it directly controls TLS verification on line 962.

---

#### 24. py/full-ssrf @ client/python/gradio_client/client.py:1342

| Field | Value |
|-------|-------|
| **Severity** | 9.1 |
| **Tags** | external/cwe/cwe-918 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.30) |
| **Iterations** | 1 |
| **Time** | 96.4s |
| **Tokens** | 6,750 |

**Message**: The full URL of this request depends on a [user-provided value](1).
The full URL of this request depends on a [user-provided value](2).
The full URL of this request depends on a [user-provided value](3).
The full URL of this request depends on a [user-provided value](4).
The full URL of this request depends on a [user-provided value](5).
The full URL of this request depends on a [user-provided value](6).
The full URL of this request depends on a [user-provided value](7).
The full URL of this request depends on a [user-provided value](8).
The full URL of this request depends on a [user-provided value](9).
The full URL of this request depends on a [user-provided value](10).
The full URL of this request depends on a [user-provided value](11).
The full URL of this request depends on a [user-provided value](12).
The full URL of this request depends on a [user-provided value](13).
The full URL of this request depends on a [user-provided value](14).

**Reasoning**: ```json
{
  "answers": [
    "Q1: The source is the `x` dictionary parameter passed to `_download_file` (line 1325). According to CodeQL's dataflow analysis, this dictionary originates from user-controlled data — specifically from user-provided values that flow through component values (text, images, audio) and are serialized into the `json_obj` at line 1128-1133, ultimately reaching `x` at line 1325. The `x["url"]` (line 1327) and `x["path"]` (line 1330) values can contain attacker-controlled c

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1344: ControlFlowNode for url_path
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1344: ControlFlowNode for url_path
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1344: ControlFlowNode for url_path
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1344: ControlFlowNode for url_path

---

### Needs More Data (1)

#### 1. py/path-injection @ gradio/routes.py:1211

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.50) |
| **Iterations** | 4 |
| **Time** | 84.9s |
| **Tokens** | 14,069 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).

**Reasoning**: After four rounds of context requests, the critical code (lines 1203-1280) where path normalization and directory traversal checks would occur remains invisible. The visible validation (lines 1198-1202) only blocks URLs/protocols — providing NO protection against '../' or absolute path traversal. While CodeQL reports this with high precision and the dataflow clearly shows user input reaching a file path sink, I cannot confirm or deny the presence of adequate path validation without seeing the actual code. This is a well-known Gradio security pattern where path validation IS typically implemented but must be verified. [No additional context available]

**Guided Question Answers**:

1. Q1: The path input originates from the 'path_or_url' parameter (line 1197) of the 'file' async function, which is a FastAPI route parameter — fully user-controlled. It can also come from file_deprecated's 'path' parameter (line 1359).
2. Q2: Not visible in provided context. The path joining logic at lines 1278-1279 is referenced in the dataflow but the actual code is not shown.
3. Q3: Partially. The dataflow indicates Path() (line 1279) is applied and abs_path (line 1207) is computed, suggesting some form of path resolution. However, the implementation is not visible to confirm whether resolve() (which follows symlinks and normalizes) vs absolute() is used.
4. Q4: NOT confirmed visible. This is the critical missing piece. No code showing 'abs_path.startswith(allowed_dir)' or equivalent check is visible in any of the provided context.
5. Q5: Potentially yes. The visible validation (lines 1198-1202) only blocks HTTP URLs and protocol-prefixed URIs — NOT '../' sequences or absolute paths like '/etc/passwd'. No traversal protection is visible in the provided context.
6. Q6: Not visible in provided context. The file operation using abs_path at line 1211 and within handle_file is not shown. handle_file's implementation was never provided.

**Dataflow Path**:
- --- Flow 1 ---
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1211: ControlFlowNode for abs_path
- --- Flow 2 ---
- line 1359: ControlFlowNode for path
- line 1360: ControlFlowNode for path
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1211: ControlFlowNode for abs_path

---

### False Positives (12)

#### 1. py/weak-sensitive-data-hashing @ gradio/oauth.py:51

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-327, external/cwe/cwe-328, external/cwe/cwe-916 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 26.9s |
| **Tokens** | 3,187 |

**Message**: [Sensitive data (password)](1) is used in a hashing algorithm (SHA256) that is insecure for password hashing, since it is not a computationally expensive hash function.
[Sensitive data (secret)](2) is used in a hashing algorithm (SHA256) that is insecure for secret hashing, since it is not a computationally expensive hash function.

**Data Flow**: OAUTH_CLIENT_SECRET env var (line 46) → concatenation with '-v4' into session_secret (line 46) → SHA256 hash (line 51) → SessionMiddleware secret_key parameter (line 51)

**Reasoning**: CodeQL flags SHA256 as insecure for password hashing, but SHA256 is NOT being used for password hashing here. It is used to derive a session cookie signing key from an OAuth client secret. The secret is never stored or compared — it's transformed into a key for itsdangerous-based cookie signing. This is a standard and secure pattern for key derivation in session middleware. The vulnerability class (weak password hashing) does not apply to this usage.

**Guided Question Answers**:

1. Q1: The source is OAUTH_CLIENT_SECRET, which is an environment variable (not visible in context but implied by naming convention). It is used on line 46.
2. Q2: OAUTH_CLIENT_SECRET (line 46) → session_secret = (OAUTH_CLIENT_SECRET or '') + '-v4' (line 46) → hashlib.sha256(session_secret.encode()).hexdigest() (line 51) → passed as secret_key to SessionMiddleware (line 51).
3. Q3: No validation or sanitization is applied to OAUTH_CLIENT_SECRET. It is directly concatenated with a version string and hashed. This is not a data injection concern — the SHA256 is used as a cookie-signing key, not for password storage.
4. Q4: The sink is hashlib.sha256(...).hexdigest() on line 51, used as the secret_key parameter for Starlette's SessionMiddleware. The operation signs session cookies using this derived key.
5. Q5: The only transformation is encoding to bytes (.encode()) and hashing with SHA256, then converting to hex (.hexdigest()). This is a key derivation operation, not a security vulnerability in context.
6. Q6: Starlette's SessionMiddleware uses itsdangerous for cookie signing. The SHA256 hash here produces a fixed-length secret key for signing. This is standard usage — the hash is not being used to 'protect' the secret but to derive a consistent signing key.
7. Q7: This code runs during application initialization (server startup), not during request handling. An attacker cannot influence this code path via HTTP requests. Only server administrators with environment variable access can set OAUTH_CLIENT_SECRET.
8. Q8: This is production initialization code in routes.py, called during app startup. It is not a test file, debug path, or dead code.
9. Q9: There is no exploitable security impact. The SHA256 here derives a session signing key from an OAuth client secret. It is not used for password storage or authentication credential comparison. A weak hash here does not enable any practical attack — the secret key is never exposed to attackers, and the hash is not used for verification against a stored value.
10. Q10: There is no weak link because the vulnerability class (weak password hashing) does not apply to this use case. SHA256 is being used for key derivation, not for storing/verifying authentication credentials. The secret key is server-side only and never exposed.

**Dataflow Path**:
- line 18: ControlFlowNode for Attribute()
- line 18: ControlFlowNode for OAUTH_CLIENT_SECRET
- line 46: ControlFlowNode for OAUTH_CLIENT_SECRET
- line 46: ControlFlowNode for session_secret
- line 51: ControlFlowNode for Attribute()

---

#### 2. py/path-injection @ gradio/utils.py:1290

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 22.0s |
| **Tokens** | 5,077 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).
This path depends on a [user-provided value](15).
This path depends on a [user-provided value](16).

**Data Flow**: source: user HTTP input (various lines 17-1359) → Path() construction (line 1279) → abspath().resolve() normalization (line 1282) → relative_to() containment check (line 1284)

**Reasoning**: The function `is_in_or_equal` is itself a SECURITY GUARD against path traversal, not a vulnerability. It normalizes both paths using `abspath().resolve()` (line 1282) which resolves all '../' sequences and symlinks, then checks containment via `relative_to()` (line 1284). This is the recommended Python pattern for preventing directory traversal. The user-controlled data flows into this check function, which then gates downstream file access — the sink at line 1290 is the security check itself, not an exploitable operation.

**Guided Question Answers**:

1. The PATH input originates from multiple sources including HTTP request data (JSON payloads with 'path' fields, Flow 3-4 via line 399's `d.path`), user-provided component values (audio/image, lines 21/17), and `path_or_url` parameters (lines 1197, 1359). These are classic user-controlled HTTP inputs in a web framework.
2. os.path.join() usage is not visible in the provided context. The code uses pathlib operations (`Path()`, `.resolve()`, `.relative_to()`) instead.
3. YES — `is_in_or_equal` explicitly normalizes both paths using `abspath(path).resolve()` on line 1282 before any comparison. This resolves `../` sequences, symlinks, and relative components into canonical absolute paths.
4. YES — After normalization, the function uses `path_1.relative_to(path_2)` (line 1284) which checks whether path_1 is contained within path_2. This is the standard Python idiom for directory containment checks and raises ValueError if path_1 escapes path_2.
5. NO — Because both paths are fully resolved via `abspath().resolve()` BEFORE the `relative_to()` check (line 1282), neither '../' sequences nor absolute paths can escape the intended directory. The canonical paths are compared directly.
6. The `is_in_or_equal` function itself performs NO file I/O operations. It is a pure boolean check used as a security guard (confirmed by the caller in `gradio/processing_utils.py` checking against `allowed_path`). File operations happen downstream only if this check returns True.

**Dataflow Path**:
- --- Flow 1 ---
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1219: ControlFlowNode for abs_path
- line 1754: ControlFlowNode for path
- line 1767: ControlFlowNode for path
- line 1282: ControlFlowNode for path_1
- line 1290: ControlFlowNode for path_1
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1290: ControlFlowNode for abspath()
- --- Flow 2 ---
- line 1359: ControlFlowNode for path
- line 1360: ControlFlowNode for path
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1219: ControlFlowNode for abs_path
- line 1754: ControlFlowNode for path
- line 1767: ControlFlowNode for path
- line 1282: ControlFlowNode for path_1
- line 1290: ControlFlowNode for path_1
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1290: ControlFlowNode for abspath()
- --- Flow 3 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 401: ControlFlowNode for path
- line 1282: ControlFlowNode for path_1
- line 1290: ControlFlowNode for path_1
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1290: ControlFlowNode for abspath()
- --- Flow 4 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 401: ControlFlowNode for path
- line 1282: ControlFlowNode for path_1
- line 1290: ControlFlowNode for path_1
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1290: ControlFlowNode for abspath()

---

#### 3. py/jinja2/autoescape-false @ gradio/component_meta.py:85

| Field | Value |
|-------|-------|
| **Severity** | 6.1 |
| **Tags** | external/cwe/cwe-079 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 35.7s |
| **Tokens** | 2,660 |

**Message**: Using jinja2 templates with autoescape=False can potentially allow XSS attacks.

**Data Flow**: events parameter + class_code parameter (function args) → events normalized to EventListener objects (lines 86-89) → template.render(events=event_template, contents=class_code) (line 90) → output written to .pyi type stub file

**Reasoning**: While the CodeQL finding correctly identifies that Jinja2 Template is used without autoescape=False, the XSS vulnerability class is inapplicable here. The function 'create_pyi' generates Python type stub (.pyi) files — not HTML output served to browsers. XSS requires an HTML rendering context in a browser, which does not exist for .pyi file generation. The data sources (class_code, events) are also internal developer-controlled metadata, not untrusted user input.

**Guided Question Answers**:

1. Q1: The data flowing into the template comes from two sources: 'events' (a list of EventListener or str passed as a parameter) and 'class_code' (a string parameter). These originate from the caller function 'create_or_modify_pyi'. In context, these are Python class definitions and event metadata, NOT untrusted user input from HTTP requests or external sources.
2. Q2: Line 85: template = Template(INTERFACE_TEMPLATE) — creates Jinja2 Template. Line 90: return template.render(events=event_template, contents=class_code) — renders template with provided data. 'event_template' is derived from the 'events' parameter (lines 86-89), and 'class_code' is passed directly to the 'contents' variable in the template.
3. Q3: No HTML-specific validation or sanitization is applied. However, the 'events' data undergoes type checking and normalization at lines 86-89 (isinstance check, EventListener construction with constrained parameters).
4. Q4: The sink is template.render() at line 90, which renders Jinja2 template content into a string. Without autoescaping, any HTML-sensitive characters in the data would pass through unescaped.
5. Q5: The events data is transformed through type-checking and EventListener object construction (lines 86-89), which constrains what data reaches the template to structured EventListener attributes rather than arbitrary strings.
6. Q6: The Jinja2 Template is created WITHOUT autoescape (default is False). However, the OUTPUT of this function is a .pyi type stub file (Python interface file), NOT an HTML response rendered in a browser. The XSS vulnerability class is not applicable to this context.
7. Q7: Not visible in provided context. However, this function is part of Gradio's internal code generation infrastructure — it generates Python type stub files during development/build, not in response to web requests.
8. Q8: This is an INTERNAL code generation function that creates .pyi type stub files. It is not a web request handler and does not produce HTML output served to browsers. It executes as part of Gradio's component meta-processing, likely at import/build time.
9. Q9: The concrete impact of XSS is NOT applicable here because the output is a Python type stub file (.pyi), not HTML served to a browser. There is no browser rendering context for script execution.
10. Q10: The weakest link is that autoescape is not enabled, but this is irrelevant because the output is a Python type stub file, not HTML. The defense is complete because there is no HTML/browser rendering context — XSS cannot occur in a .pyi file.

---

#### 4. py/jinja2/autoescape-false @ gradio/events.py:584

| Field | Value |
|-------|-------|
| **Severity** | 6.1 |
| **Tags** | external/cwe/cwe-079 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | High (0.92) |
| **Iterations** | 1 |
| **Time** | 26.7s |
| **Tokens** | 4,280 |

**Message**: Using jinja2 templates with autoescape=False can potentially allow XSS attacks.

**Data Flow**: self.listener.__doc__ (line 583, developer-controlled docstring) → Template(self.listener.__doc__).render(component=component) (line 583) → self.listener.__doc__ (line 584, Python docstring attribute, NOT HTML output)

**Reasoning**: While it's true that Jinja2 Template is used without autoescape=True, the rendered output is assigned to a Python docstring attribute (line 584), not served as HTML to end users. Both the template content (self.listener.__doc__) and the template variable (component) are developer-controlled, not attacker-controlled. The XSS attack vector is not applicable since there is no HTML rendering context — this is purely internal documentation string processing.

**Guided Question Answers**:

1. Q1: The source data is `self.listener.__doc__` — the Python docstring of a listener callable (line 583). This is developer-written internal code, NOT user/external input.
2. Q2: `self.listener.__doc__` (line 583) → `Template(self.listener.__doc__)` (line 583) → `.render(component=component)` (line 583) → `doc` (line 583) → `self.listener.__doc__ = doc` (line 584).
3. Q3: No explicit sanitization is applied. However, the source is a developer-controlled docstring, not external input. The `component` parameter is a string identifying a Gradio component type.
4. Q4: The sink is the Jinja2 Template rendering at line 583: `Template(self.listener.__doc__).render(component=component)`. The rendered output replaces the listener's docstring at line 584.
5. Q5: The template string is simply rendered by Jinja2. No intermediate transformations occur between source and sink that would bypass sanitization.
6. Q6: The finding correctly notes that `Template()` is used without `autoescape=True`. Jinja2 does NOT auto-escape by default when using the `Template` constructor directly. However, since the output is assigned to a Python docstring (line 584) and NOT rendered in an HTML context, XSS protection is moot.
7. Q7: This code runs during internal Gradio event listener setup. The `component` parameter is a developer-provided string identifying a component type. An end-user attacker cannot control either the template or the `component` parameter.
8. Q8: This is production code in an internal framework setup path. The docstrings being templated are developer-written (part of the Gradio library or user-defined listener functions). The output goes to a Python docstring, not to an HTTP response or HTML page.
9. Q9: The potential impact would be XSS, but the rendered docstring is NOT served as HTML to any end user. It is assigned to a Python object's `__doc__` attribute for internal documentation purposes.
10. Q10: There is no weak link in the defense chain for XSS because the rendered output is a Python docstring, not HTML served to users. Both the template (`self.listener.__doc__`) and the variable (`component`) are developer-controlled. The XSS vulnerability class does not apply to this sink.

---

#### 5. py/path-injection @ client/python/gradio_client/client.py:1352

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.90) |
| **Iterations** | 1 |
| **Time** | 30.7s |
| **Tokens** | 5,826 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: source: x["path"] from remote server response (line 1328) → concatenated into url_path (line 1328) → Path(url_path).name extracts basename only (lines 1342, 1347, 1348) → written to controlled temp_dir and then moved to controlled output directory

**Reasoning**: While x['path'] from the remote server response does flow into path construction without explicit sanitization, the code uses Path(url_path).name at lines 1342, 1347, and 1348, which extracts only the basename (final path component). This effectively neutralizes directory traversal attempts because '../' sequences and absolute paths are stripped. The file is always written into the controlled temp_dir and moved to a controlled output subdirectory, preventing path escape.

**Guided Question Answers**:

1. Q1: The path input originates from x["path"] at line 1328 of _download_file. The dict 'x' is passed to this function and contains a 'path' key whose value comes from a remote Gradio server's JSON response (via json_obj at line 1128-1133 per the dataflow). This is server-returned data, not directly a user request parameter, but it IS untrusted remote data.
2. Q2: No, os.path.join() is not used. String concatenation is used instead: self.root_url + "file=" + x["path"] (line 1328). In the non-stream case, the path from the remote server is directly concatenated into a URL. In the stream case, x["url"] is used. For filesystem operations, Path(url_path).name is used (lines 1342, 1347, 1348).
3. Q3: No normalization is applied. Path(url_path).name is used, which extracts just the filename portion (equivalent to basename), but the url_path itself is not normalized with os.path.realpath() or os.path.abspath(). The final return uses str(dest.resolve()) (line 1349), but this is a resolution, not a security check.
4. Q4: No check is performed to verify the resulting path starts with an allowed base directory. The code constructs a destination directory as Path(self.client.output_dir) / sha.hexdigest() and places the file there, but no validation is done against the path.
5. Q5: '../' sequences and absolute paths are effectively mitigated by the use of Path(url_path).name. This property extracts only the final component (the filename) from the path, stripping any directory components. For example, Path("http://evil.com/../../../etc/passwd").name returns 'passwd', and Path("/etc/shadow").name returns 'shadow'. This means the file is written into the controlled temp_dir or the controlled output directory, not at an attacker-controlled path.
6. Q6: File WRITE operations are performed: (1) downloading via HTTP GET stream and writing to temp_dir / Path(url_path).name (lines 1341-1345), (2) creating directory with mkdir (line 1347), and (3) moving the downloaded file via shutil.move (line 1348) and returning the resolved path (line 1349).

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1352: ControlFlowNode for BinaryExpr
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1352: ControlFlowNode for BinaryExpr
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1352: ControlFlowNode for BinaryExpr
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1352: ControlFlowNode for BinaryExpr

---

#### 6. py/path-injection @ client/python/gradio_client/client.py:1361

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.90) |
| **Iterations** | 1 |
| **Time** | 39.4s |
| **Tokens** | 6,030 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: source: x['path'] from server response (line 1325) → string concatenation into url_path (line 1328) → Path(url_path).name extracts filename (lines 1348, 1359) → dest constructed from output_dir / hash / filename (line 1359) → shutil.move executes file move (line 1360) → str(dest.resolve()) returns path string (line 1361)

**Reasoning**: The sink at line 1361 is `str(dest.resolve())` which is a pure string conversion — no file I/O occurs at this line. All actual file operations use `Path(url_path).name` (lines 1348, 1359), which strips directory components and neutralizes `../` traversal sequences. While `x['path']` is user-influenced and flows into the URL for the HTTP request (a separate concern), the local filesystem path construction is protected by the `.name` property extraction. The `shutil.move()` on line 1360 is the actual file operation, and its destination is safely constructed.

**Guided Question Answers**:

1. The path input originates from `x['path']`, a value from a dictionary passed to `_download_file()`. As shown in the dataflow traces, `x` flows from user-provided values (e.g., inputs/text sent by the client, line 1325). This is data received from a Gradio server response, derived from user-provided input values (lines 5, 17, 21, 49 of the traced flows).
2. No, `os.path.join()` is NOT used. Instead, the code uses string concatenation at line 1328: `self.root_url + 'file=' + x['path']` to build the URL. For the local file path construction, `Path(self.client.output_dir) / sha.hexdigest()` builds the directory safely via a SHA-256 hash (line 1358), and `Path(url_path).name` extracts just the filename component for the destination path (line 1359).
3. The URL is NOT normalized, but it is used as an HTTP GET URL (line 1332), NOT as a local filesystem path. For the local filesystem path, `Path(url_path).name` on line 1359 strips all directory components, extracting only the final filename segment. The final return on line 1361 calls `str(dest.resolve())`, which does normalize the path.
4. There is NO explicit check that the resolved path starts with the allowed base directory. However, the `dest` path is constructed from `Path(self.client.output_dir) / sha.hexdigest() / Path(url_path).name`, where the SHA component is server-controlled and `Path(...).name` strips directory traversal sequences. Line 1361 only returns the string representation of this already-constructed path.
5. Directory traversal via `../` sequences in `x['path']` would affect the URL sent to the server (line 1328), potentially allowing access to unintended server-side files. However, for the local filesystem path, `Path(url_path).name` on lines 1348 and 1359 strips all directory components, so `../` sequences would be removed before the local file is written or moved. An absolute path like `/etc/passwd` would also be reduced to just `passwd` by `.name`.
6. The file operations performed are: (1) Creating a temporary directory with `temp_dir.mkdir()` (line 1330), (2) Writing the downloaded content to a temp file via `f.write(chunk)` (line 1348), (3) Creating the output directory with `directory.mkdir()` (line 1358), (4) Moving the temp file to the destination with `shutil.move()` (line 1360). The sink at line 1361 is `str(dest.resolve())` which merely converts the path to a string — no file operation occurs at this line.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1361: ControlFlowNode for dest
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1361: ControlFlowNode for dest
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1361: ControlFlowNode for dest
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 1325: ControlFlowNode for x
- line 1328: ControlFlowNode for url_path
- line 1359: ControlFlowNode for dest
- line 1361: ControlFlowNode for dest

---

#### 7. py/path-injection @ gradio/components/file_explorer.py:92

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | High (0.90) |
| **Iterations** | 1 |
| **Time** | 31.9s |
| **Tokens** | 3,901 |

**Message**: This path depends on a [user-provided value](1).

**Data Flow**: root_dir parameter (line 8, developer-controlled constructor arg) → os.path.abspath(root_dir) (line 91) → os.path.exists(abs_root_dir) check (line 92) → self.root_dir = DeveloperPath(abs_root_dir) (line 96)

**Reasoning**: The `root_dir` parameter is a constructor argument set by the application developer in server-side Python code, not an HTTP request parameter or user-controlled input. CodeQL's dataflow appears to trace from the constructor parameter definition (line 8) to its use (line 91-92), flagging any external input, but in this framework architecture, constructor parameters are developer-controlled. The path is normalized via os.path.abspath (line 91) and validated to exist and be a directory (lines 92-94), then wrapped in DeveloperPath (line 96), which is Gradio's explicit marker for developer-trusted paths. There is no path injection vulnerability here.

**Guided Question Answers**:

1. The 'path input' here is the `root_dir` parameter (line 8) of what appears to be a constructor (`__init__`) for a FileExplorer component. In the Gradio framework, component constructor parameters are set by the application developer in server-side Python code — NOT by end-user HTTP request parameters, form fields, or query strings.
2. No. `os.path.join()` is not used in this code. The code uses `os.path.abspath(root_dir)` on line 91.
3. Yes. `os.path.abspath(root_dir)` is called on line 91 to produce `abs_root_dir`. Note that `os.path.abspath` resolves relative paths against the CWD but does NOT resolve symlinks (unlike `os.path.realpath`).
4. After normalization, the code checks that the path exists (`os.path.exists`, line 92) and is a directory (`os.path.isdir`, line 94). However, there is NO check that the resolved path starts with or is confined to some allowed base directory — because `root_dir` IS the intended base directory itself. The path is wrapped in `DeveloperPath` on line 96, which in Gradio's design marks it as a developer-controlled, trusted path.
5. Since `root_dir` is the developer-defined base directory (not user-controlled), the question of escaping via '../' is not applicable in the traditional path-traversal sense. A developer setting their own `root_dir` to any path (including one with '../') is intentional behavior, not a vulnerability.
6. In this code snippet, the only file operations are `os.path.abspath` (line 91), `os.path.exists` (line 92), and `os.path.isdir` (line 94). These are existence/type checks on the developer-specified root directory, not operations on arbitrary user-supplied file paths.

**Dataflow Path**:
- line 8: ControlFlowNode for Attribute()
- line 8: ControlFlowNode for dd
- line 28: ControlFlowNode for dd
- line 28: ControlFlowNode for s
- line 28: ControlFlowNode for s
- line 46: ControlFlowNode for root_dir
- line 91: ControlFlowNode for root_dir
- line 91: ControlFlowNode for Attribute()
- line 91: ControlFlowNode for abs_root_dir
- line 92: ControlFlowNode for abs_root_dir

---

#### 8. py/path-injection @ gradio/components/file_explorer.py:94

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.70) |
| **Iterations** | 2 |
| **Time** | 51.5s |
| **Tokens** | 8,660 |

**Message**: This path depends on a [user-provided value](1).

**Data Flow**: source: root_dir constructor parameter (line 6, developer-controlled, not end-user input) → os.path.abspath(root_dir) normalization (line 80) → existence/isdir checks only (lines 81-84, no containment check) → self.root_dir = DeveloperPath(abs_root_dir) (line 85)

**Reasoning**: The root_dir parameter is a developer-specified constructor argument, not an end-user HTTP input. No external callers were found, and in Gradio's architecture, root_dir is set programmatically by the application developer. While the code lacks explicit containment checks (no verification that abs_root_dir is within an expected base directory), the path-injection vulnerability requires user-controlled input reaching the sink. Developer-chosen configuration values do not constitute a path injection vulnerability, even though the code could be hardened with additional containment checks.

**Guided Question Answers**:

1. Q1: The root_dir parameter originates as a constructor argument (line 6). No external callers were found, meaning it is instantiated by Gradio framework code (not shown). In Gradio, root_dir is set by the application developer, not by end users via HTTP requests. The CodeQL source trace pointing to line 8 appears to be tracking the parameter itself, not provenance from HTTP input.
2. Q2: os.path.join() is NOT used in the visible code. root_dir is passed directly to os.path.abspath() on line 80.
3. Q3: YES — os.path.abspath() is called on line 80: `abs_root_dir = os.path.abspath(root_dir)`. This resolves relative paths and '..' sequences to produce a canonical absolute path.
4. Q4: NO — there is no check that abs_root_dir starts with or is contained within a specific allowed base directory. Only existence (line 81) and isdir (line 83) checks are performed.
5. Q5: While '../' sequences are resolved by abspath, an attacker providing root_dir='/etc' or any absolute path would pass all visible checks. However, root_dir is a developer-specified parameter, not end-user HTTP input.
6. Q6: The visible code stores the path as self.root_dir = DeveloperPath(abs_root_dir) (line 85). FileExplorer lists/displays files from this directory. No destructive file operations (write, delete) are visible in this code.

**Dataflow Path**:
- line 8: ControlFlowNode for Attribute()
- line 8: ControlFlowNode for dd
- line 28: ControlFlowNode for dd
- line 28: ControlFlowNode for s
- line 28: ControlFlowNode for s
- line 46: ControlFlowNode for root_dir
- line 91: ControlFlowNode for root_dir
- line 91: ControlFlowNode for Attribute()
- line 91: ControlFlowNode for abs_root_dir
- line 94: ControlFlowNode for abs_root_dir

---

#### 9. py/request-without-cert-validation @ client/python/gradio_client/client.py:597

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-295 |
| **Tool** | CodeQL |
| **Precision** | medium |
| **Confidence** | Medium (0.70) |
| **Iterations** | 1 |
| **Time** | 30.9s |
| **Tokens** | 2,670 |

**Message**: This request may run without certificate validation because [it is disabled](1) by [this value](2).

**Data Flow**: self.ssl_verify (set at init, not visible) → verify=self.ssl_verify (line 602) → httpx.get() call (lines 598-604)

**Reasoning**: This is a False Positive for a vulnerability IN THIS CODE. The `verify=self.ssl_verify` parameter on line 602 is an intentional, user-configurable option that defaults to True (standard httpx behavior). The CodeQL finding flags that certificate validation CAN be disabled, but this requires the user to explicitly set `self.ssl_verify=False` at client initialization. The library is providing a legitimate configuration option (common for development/testing with self-signed certs), not introducing a vulnerability. The code correctly passes the user's choice through to httpx.

**Guided Question Answers**:

1. Q1: The 'dangerous' data in this context is the `self.ssl_verify` parameter. Its ultimate source is a user-configurable parameter passed during class instantiation (not visible in the provided code context), which controls whether SSL certificate verification is performed on outgoing HTTP requests.
2. Q2: The data flows from `self.ssl_verify` (class attribute, source unknown — set during __init__) directly to the `verify` keyword argument in the `httpx.get()` call on line 602. The intermediate variables are `self.ssl_verify` (line 602) which is passed as `verify=self.ssl_verify` to httpx.get().
3. Q3: There is NO validation or sanitization on `self.ssl_verify` visible in this code. The value is passed directly to `httpx.get()`. The CodeQL message indicates the value may be `False`, which would disable certificate validation. There is no check like `if self.ssl_verify is False: warn(...)` or any enforcement.
4. Q4: The sink is the `httpx.get()` call on lines 598-604, specifically the `verify=self.ssl_verify` parameter. When `verify=False`, httpx will not validate SSL/TLS server certificates, making the connection vulnerable to man-in-the-middle attacks.
5. Q5: No transformations occur. The `self.ssl_verify` value is passed directly and unchanged to the httpx library's `verify` parameter.
6. Q6: The httpx library does NOT provide automatic certificate validation when `verify=False` — this is the explicit purpose of the parameter. Disabling it removes the library's built-in TLS certificate verification. No other framework-level protection compensates for this.
7. Q7: This code runs whenever a client connects to a Gradio server to fetch API info. An attacker would need to be in a MITM position on the network path between client and server. The attacker does NOT need authentication on either end — they exploit the disabled certificate validation passively.
8. Q8: This is production code in the main client module, NOT test or debug code. It executes on every client connection to a Gradio server with app_version > 3.36.1, which is a normal and expected code path.
9. Q9: The concrete security impact is a Man-in-the-Middle (MITM) attack enabling: interception of API information, potential injection of malicious API responses that could lead to further exploitation (e.g., manipulating client behavior), and information disclosure about the server's API structure.
10. Q10: The weakest link is that `self.ssl_verify` can be set to `False` and is passed directly to `httpx.get()` with no guardrails. However, this is a **design choice** — the library intentionally allows users to disable SSL verification (e.g., for self-signed certificates in development). The vulnerability exists only if a user explicitly sets `ssl_verify=False`, which is a user-controlled configuration option.

---

#### 10. py/clear-text-logging-sensitive-data @ demo/blocks_flashcards/run.py:13

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | external/cwe/cwe-312, external/cwe/cwe-359, external/cwe/cwe-532 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.65) |
| **Iterations** | 1 |
| **Time** | 30.6s |
| **Tokens** | 4,800 |

**Message**: This expression logs [sensitive data (private)](1) as clear text.

**Data Flow**: source (line 55, sorted/unique_sex) → multiple Gradio internal transformations → flashcards_table.value (line 12-13) → print() sink (line 13)

**Reasoning**: The code is in a demo file (demo/blocks_flashcards/run.py) and uses print() for debugging purposes during UI event handling. While print() does write to stdout without sanitization, this is demo/example code where print() is commonly used to demonstrate component behavior. The flagged pattern is a debug print in a demo application, not a production security vulnerability. The data flowing through (flashcard table values) is user-generated flashcard content, not inherently sensitive credentials or PII that would warrant a 7.5 severity rating. The finding is technically accurate (print is clear-text logging) but pragmatically a false positive for a security concern.

**Guided Question Answers**:

1. Q1: The source is identified by CodeQL as `sorted()` at line 55, with data flowing through `unique_sex` and a complex path of Gradio component initial values. The exact nature of this data is NOT visible in the provided code snippet, which only shows the single flagged line.
2. Q2: The dataflow path provided by CodeQL is extremely long (spanning lines 55, 98, 247, 252, 207, 208, 215, 412, 481, 1128, 1145, 480, 214, 134, 64, 12, 13) but ONLY line 13 is visible in the provided context. The intermediate variables cannot be verified.
3. Q3: No validation, sanitization, or encoding is visible in the provided single-line context. However, the broader codebase context is completely missing.
4. Q4: The sink is `print()` on line 13. The code `print(flashcards_table.value)` outputs the table's value to stdout. This is a logging/information disclosure concern rather than injection.
5. Q5: The dataflow path involves numerous transformations (tuple construction, list operations, JSON traversal, f-string formatting) but none of these are visible in the provided context.
6. Q6: No framework-level protections apply to `print()` — it is a raw Python standard library function that writes directly to stdout without any filtering or encoding.
7. Q7: Not visible in provided context. The `flashcards_table.change()` event handler triggers on user interaction with a Gradio UI component, suggesting authenticated or unauthenticated user access depending on the app's deployment.
8. Q8: The code is in `demo/blocks_flashcards/run.py`, which appears to be a **demo/example/test file** for the Gradio library. The file name and path suggest this is not production application code but rather a demonstration of the flashcards feature.
9. Q9: The security impact is **information disclosure** — if `flashcards_table.value` contains sensitive data (passwords, PII, API keys), printing it to stdout would expose that data in application logs, console output, or debugging traces. The severity (7.5) reflects that `print()` can route data to log aggregation systems.
10. Q10: The weakest link is the direct `print()` call with no filtering of sensitive fields. However, the actual sensitivity of `flashcards_table.value` cannot be confirmed from this context. This appears to be demo/debug code in a demo file.

**Dataflow Path**:
- --- Flow 1 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for Attribute()
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1145: ControlFlowNode for json_obj
- line 480: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for move_files_to_cache()
- line 214: [post] ControlFlowNode for self [Attribute value]
- line 134: ControlFlowNode for self [Return] [Attribute value]
- line 64: [post] ControlFlowNode for self [Attribute value]
- line 64: ControlFlowNode for self [Return] [Attribute value]
- line 12: ControlFlowNode for Attribute() [Attribute value]
- line 12: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for Attribute
- --- Flow 2 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for Attribute()
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for Attribute() [Tuple element at index 1]
- line 207: ControlFlowNode for Tuple [Tuple element at index 1]
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 154: ControlFlowNode for value
- line 165: ControlFlowNode for value
- line 165: ControlFlowNode for List [List element]
- line 165: ControlFlowNode for value [List element]
- line 166: ControlFlowNode for value [List element]
- line 208: ControlFlowNode for Attribute() [List element]
- line 208: ControlFlowNode for initial_value [List element]
- line 215: ControlFlowNode for initial_value [List element]
- line 412: ControlFlowNode for data [List element]
- line 481: ControlFlowNode for data [List element]
- line 1128: ControlFlowNode for json_obj [List element]
- line 1133: ControlFlowNode for json_obj [List element]
- line 1706: ControlFlowNode for s [List element]
- line 1706: ControlFlowNode for s [List element]
- line 1706: ControlFlowNode for Subscript
- line 1133: ControlFlowNode for func()
- line 480: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for move_files_to_cache()
- line 214: [post] ControlFlowNode for self [Attribute value]
- line 134: ControlFlowNode for self [Return] [Attribute value]
- line 64: [post] ControlFlowNode for self [Attribute value]
- line 64: ControlFlowNode for self [Return] [Attribute value]
- line 12: ControlFlowNode for Attribute() [Attribute value]
- line 12: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for Attribute
- --- Flow 3 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for Attribute()
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 92: ControlFlowNode for value
- line 99: ControlFlowNode for IfExp
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 812: ControlFlowNode for x
- line 812: ControlFlowNode for Fstring
- line 1133: ControlFlowNode for func()
- line 480: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for move_files_to_cache()
- line 214: [post] ControlFlowNode for self [Attribute value]
- line 134: ControlFlowNode for self [Return] [Attribute value]
- line 64: [post] ControlFlowNode for self [Attribute value]
- line 64: ControlFlowNode for self [Return] [Attribute value]
- line 12: ControlFlowNode for Attribute() [Attribute value]
- line 12: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for Attribute
- --- Flow 4 ---
- line 55: ControlFlowNode for sorted()
- line 55: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for unique_sex
- line 98: ControlFlowNode for Attribute()
- line 247: ControlFlowNode for value()
- line 247: ControlFlowNode for initial_value
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 240: ControlFlowNode for value
- line 252: ControlFlowNode for value
- line 252: ControlFlowNode for List [List element]
- line 252: ControlFlowNode for value [List element]
- line 256: ControlFlowNode for value [List element]
- line 208: ControlFlowNode for Attribute() [List element]
- line 208: ControlFlowNode for initial_value [List element]
- line 215: ControlFlowNode for initial_value [List element]
- line 412: ControlFlowNode for data [List element]
- line 481: ControlFlowNode for data [List element]
- line 1128: ControlFlowNode for json_obj [List element]
- line 1141: ControlFlowNode for json_obj [List element]
- line 1141: ControlFlowNode for item
- line 1142: ControlFlowNode for item
- line 1128: ControlFlowNode for json_obj
- line 1145: ControlFlowNode for json_obj
- line 1142: ControlFlowNode for traverse()
- line 1142: [post] ControlFlowNode for new_obj
- line 1143: ControlFlowNode for new_obj
- line 480: ControlFlowNode for Attribute()
- line 214: ControlFlowNode for move_files_to_cache()
- line 214: [post] ControlFlowNode for self [Attribute value]
- line 134: ControlFlowNode for self [Return] [Attribute value]
- line 64: [post] ControlFlowNode for self [Attribute value]
- line 64: ControlFlowNode for self [Return] [Attribute value]
- line 12: ControlFlowNode for Attribute() [Attribute value]
- line 12: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for flashcards_table [Attribute value]
- line 13: ControlFlowNode for Attribute

---

#### 11. py/path-injection @ client/python/gradio_client/utils.py:1227

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.65) |
| **Iterations** | 2 |
| **Time** | 42.1s |
| **Tokens** | 8,222 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: User input (HTTP request parameters, lines ~5-49) → intermediate processing through 'inputs', 'json_obj', 'value' (multiple transform steps across the codebase) → parameter 's' in is_filepath (line 1223) → Path(s) construction with .exists() and .is_file() checks (line 1227, sink)

**Reasoning**: While the CodeQL dataflow correctly traces user input reaching the Path() constructor at line 1227 without sanitization, the actual security impact is minimal. The function only performs Path.exists() and Path.is_file() — read-only filesystem metadata checks that don't read, write, or exfiltrate file contents. An attacker could at most probe for file existence on the server. Additionally, the static analyzer found no callers of is_filepath within the repository, meaning either this is dead code or it's called via dynamic dispatch the analyzer can't trace. Without confirmed callers performing dangerous file operations on the returned path, this doesn't constitute a meaningful path injection vulnerability.

**Guided Question Answers**:

1. The path input originates from user-provided values (HTTP request data/API inputs) according to the dataflow traces. These flow through 'inputs', 'json_obj', 'value', and ultimately into parameter 's' of is_filepath. The full source context is not visible in the provided code.
2. os.path.join() is not used in the visible code. The user-provided string 's' flows directly into Path(s) at line 1227.
3. No normalization is performed. There is no call to os.path.realpath(), os.path.abspath(), or pathlib.resolve() anywhere in the visible code.
4. No. There is no check that the resulting path starts with an allowed base directory.
5. Yes. Since 's' is used directly in Path(s) without sanitization, '../' sequences or absolute paths like '/etc/passwd' could be used to point to any file on the filesystem.
6. The function only performs Path(s).exists() and Path(s).is_file() — these are read-only stat/metadata operations. No file read, write, or delete is performed within this function, and no callers were found by the static analyzer.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1132: ControlFlowNode for json_obj
- line 1685: ControlFlowNode for s
- line 1686: ControlFlowNode for s
- line 1223: ControlFlowNode for s
- line 1227: ControlFlowNode for Path()

---

#### 12. py/path-injection @ gradio/utils.py:1353

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Medium (0.65) |
| **Iterations** | 2 |
| **Time** | 59.6s |
| **Tokens** | 10,256 |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).
This path depends on a [user-provided value](11).
This path depends on a [user-provided value](12).
This path depends on a [user-provided value](13).
This path depends on a [user-provided value](14).

**Data Flow**: User input (FileData.path, line 399→402) → file_path parameter (line 1336) → isinstance checks (lines 1340, 1343) → Path(file_path) (line 1343) → file_path.exists() on unnormalized path (line 1345) → is_in_or_equal(file_path, static_file) with abspath normalization (line 1353)

**Reasoning**: The function `_is_static_file` is a security GATE (returns bool) that checks whether a path matches a whitelisted set of static files. The critical comparison in `is_in_or_equal` (line 1353) normalizes paths via `abspath`, resolving `../` sequences before comparison. A directory traversal payload like `../../etc/passwd` would be resolved to its absolute form and fail to match any `static_file` entry, returning False. While `file_path.exists()` (line 1345) operates on the unnormalized path, it's a stat-like operation that does not expose file contents. The real concern is whether callers properly gate file serving on the return value, but the function itself is a protective check, not a sink.

**Guided Question Answers**:

1. The PATH input originates from user-provided values flowing through multiple paths (audio, original_image, text inputs, file uploads) as shown in the dataflow traces. The `file_path` parameter to `_is_static_file` comes from a FileData object's `.path` attribute (line 399 → 402 → 1336) or directly from user input. The exact HTTP entry point is not fully visible in the provided context.
2. No `os.path.join()` usage is visible in `_is_static_file`. The function uses `Path(file_path)` (pathlib) to convert the string to a Path object on line 1343.
3. No path normalization with `os.path.realpath()` or `os.path.abspath()` is performed WITHIN `_is_static_file` before the `file_path.exists()` call on line 1345. `is_in_or_equal` calls `abspath`, but this normalization happens AFTER `exists()` is already called.
4. After normalization in `is_in_or_equal` (which calls `abspath`), the path is compared to static files. However, there is no explicit check that the result starts with an allowed base directory. The comparison logic in `is_in_or_equal` (comparing to `static_file` list entries) acts as an implicit boundary check, though the exact implementation is not visible.
5. The `file_path.exists()` call on line 1345 uses the UNNORMALIZED path. However, `is_in_or_equal` calls `abspath` which resolves `../` sequences, so the actual path comparison at line 1353 is performed on resolved paths. An absolute path like `/etc/passwd` would not match any `static_file` entry and the function would return False, blocking it.
6. The only file operations are: `file_path.exists()` (line 1345, a stat/read metadata operation) and the path comparison in `is_in_or_equal` (line 1353, which calls `abspath`). No file content is read, written, or deleted within this function. The function is a security gate returning True/False.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 402: ControlFlowNode for path
- line 1336: ControlFlowNode for file_path
- line 1340: ControlFlowNode for file_path
- line 1343: ControlFlowNode for file_path
- line 1353: ControlFlowNode for file_path
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 402: ControlFlowNode for path
- line 1336: ControlFlowNode for file_path
- line 1340: ControlFlowNode for file_path
- line 1343: ControlFlowNode for file_path
- line 1353: ControlFlowNode for file_path
- --- Flow 3 ---
- line 5: ControlFlowNode for text
- line 7: ControlFlowNode for Subscript
- line 1514: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1540: ControlFlowNode for list() [List element]
- line 1540: ControlFlowNode for inputs [List element]
- line 1541: ControlFlowNode for inputs [List element]
- line 1668: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for inputs [List element]
- line 1683: ControlFlowNode for Subscript
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 402: ControlFlowNode for path
- line 1336: ControlFlowNode for file_path
- line 1340: ControlFlowNode for file_path
- line 1343: ControlFlowNode for file_path
- line 1353: ControlFlowNode for file_path
- --- Flow 4 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 112: ControlFlowNode for value
- line 122: ControlFlowNode for value
- line 208: ControlFlowNode for Attribute()
- line 208: ControlFlowNode for initial_value
- line 215: ControlFlowNode for initial_value
- line 412: ControlFlowNode for data
- line 481: ControlFlowNode for data
- line 1128: ControlFlowNode for json_obj
- line 1133: ControlFlowNode for json_obj
- line 397: ControlFlowNode for d
- line 399: ControlFlowNode for d
- line 399: ControlFlowNode for Attribute()
- line 399: ControlFlowNode for path
- line 402: ControlFlowNode for path
- line 1336: ControlFlowNode for file_path
- line 1340: ControlFlowNode for file_path
- line 1343: ControlFlowNode for file_path
- line 1353: ControlFlowNode for file_path

---

### Errors (12)

#### 1. py/path-injection @ gradio/routes.py:1211

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.3s |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- --- Flow 1 ---
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1211: ControlFlowNode for abs_path
- --- Flow 2 ---
- line 1359: ControlFlowNode for path
- line 1360: ControlFlowNode for path
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1211: ControlFlowNode for abs_path

---

#### 2. py/path-injection @ gradio/routes.py:1249

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.2s |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- --- Flow 1 ---
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1249: ControlFlowNode for abs_path
- --- Flow 2 ---
- line 1359: ControlFlowNode for path
- line 1360: ControlFlowNode for path
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1249: ControlFlowNode for abs_path

---

#### 3. py/path-injection @ gradio/routes.py:1254

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.1s |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- --- Flow 1 ---
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1254: ControlFlowNode for abs_path
- --- Flow 2 ---
- line 1359: ControlFlowNode for path
- line 1360: ControlFlowNode for path
- line 1197: ControlFlowNode for path_or_url
- line 1207: ControlFlowNode for path_or_url
- line 1278: ControlFlowNode for path
- line 1279: ControlFlowNode for str()
- line 1279: ControlFlowNode for Attribute()
- line 1279: ControlFlowNode for Path()
- line 1207: ControlFlowNode for Attribute()
- line 1207: ControlFlowNode for abs_path
- line 1254: ControlFlowNode for abs_path

---

#### 4. py/path-injection @ gradio/routes.py:2413

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.3s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 2402: ControlFlowNode for hash
- line 2411: ControlFlowNode for snapshot_file
- line 2413: ControlFlowNode for snapshot_file

---

#### 5. py/path-injection @ gradio/routes.py:2417

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.0s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 2402: ControlFlowNode for hash
- line 2411: ControlFlowNode for snapshot_file
- line 2417: ControlFlowNode for snapshot_file

---

#### 6. py/path-injection @ demo/file_explorer/run.py:9

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.1s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 8: ControlFlowNode for file
- line 9: ControlFlowNode for Path()

---

#### 7. py/path-injection @ demo/file_explorer/run.py:11

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 3.8s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 8: ControlFlowNode for file
- line 11: ControlFlowNode for Path()

---

#### 8. py/path-injection @ demo/stream_audio_out/run.py:25

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.2s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 13: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for format
- line 31: ControlFlowNode for format
- line 16: ControlFlowNode for format
- line 24: ControlFlowNode for file
- line 25: ControlFlowNode for Attribute

---

#### 9. py/path-injection @ demo/stream_audio_out/run.py:49

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.2s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 47: ControlFlowNode for audio_file
- line 49: ControlFlowNode for audio_file

---

#### 10. py/path-injection @ demo/image_editor_story/run.py:9

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.0s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 6: ControlFlowNode for im
- line 9: ControlFlowNode for Path()

---

#### 11. py/path-injection @ demo/html_upload/run.py:29

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.0s |

**Message**: This path depends on a [user-provided value](1).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- line 29: ControlFlowNode for path
- line 29: ControlFlowNode for Path()

---

#### 12. py/path-injection @ gradio/components/upload_button.py:229

| Field | Value |
|-------|-------|
| **Severity** | 7.5 |
| **Tags** | correctness, external/cwe/cwe-022, external/cwe/cwe-023, external/cwe/cwe-036, external/cwe/cwe-073, external/cwe/cwe-099 |
| **Tool** | CodeQL |
| **Precision** | high |
| **Confidence** | Low (0.00) |
| **Iterations** | 1 |
| **Time** | 2.0s |

**Message**: This path depends on a [user-provided value](1).
This path depends on a [user-provided value](2).
This path depends on a [user-provided value](3).
This path depends on a [user-provided value](4).
This path depends on a [user-provided value](5).
This path depends on a [user-provided value](6).
This path depends on a [user-provided value](7).
This path depends on a [user-provided value](8).
This path depends on a [user-provided value](9).
This path depends on a [user-provided value](10).

**Reasoning**: LLM call failed: litellm.RateLimitError: RateLimitError: OpenAIException - Your account's current usage pattern does not comply with the Fair Usage Policy, and your request frequency has been limited. For details, please refer to the Subscription Service Agreement. To restore access, please submit a request.

**Dataflow Path**:
- --- Flow 1 ---
- line 21: ControlFlowNode for Attribute()
- line 11: ControlFlowNode for audio
- line 15: ControlFlowNode for audio
- line 85: ControlFlowNode for value
- line 206: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 231: ControlFlowNode for value
- line 225: ControlFlowNode for .0
- line 231: ControlFlowNode for file
- line 229: ControlFlowNode for Path()
- --- Flow 2 ---
- line 17: ControlFlowNode for Attribute()
- line 13: ControlFlowNode for original_image
- line 14: ControlFlowNode for original_image
- line 57: ControlFlowNode for value
- line 182: ControlFlowNode for value
- line 405: ControlFlowNode for kwargs [Dictionary element at key value]
- line 406: ControlFlowNode for kwargs [Dictionary element at key value]
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 231: ControlFlowNode for value
- line 225: ControlFlowNode for .0
- line 231: ControlFlowNode for file
- line 229: ControlFlowNode for Path()
- --- Flow 3 ---
- line 49: ControlFlowNode for Attribute()
- line 49: ControlFlowNode for name2
- line 81: ControlFlowNode for name2
- line 76: ControlFlowNode for name
- line 77: ControlFlowNode for name
- line 77: ControlFlowNode for list()
- line 55: ControlFlowNode for value
- line 141: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 231: ControlFlowNode for value
- line 225: ControlFlowNode for .0
- line 231: ControlFlowNode for file
- line 229: ControlFlowNode for Path()
- --- Flow 4 ---
- line 23: ControlFlowNode for Attribute()
- line 23: ControlFlowNode for code_in
- line 34: ControlFlowNode for code_in
- line 15: ControlFlowNode for code
- line 16: ControlFlowNode for code
- line 67: ControlFlowNode for value
- line 171: ControlFlowNode for value
- line 135: ControlFlowNode for value
- line 207: ControlFlowNode for value
- line 243: ControlFlowNode for value
- line 248: ControlFlowNode for load_fn
- line 252: ControlFlowNode for Tuple
- line 207: ControlFlowNode for Attribute()
- line 207: ControlFlowNode for initial_value
- line 208: ControlFlowNode for initial_value
- line 213: ControlFlowNode for value
- line 222: ControlFlowNode for value
- line 193: ControlFlowNode for value
- line 211: ControlFlowNode for value
- line 222: ControlFlowNode for Attribute()
- line 222: ControlFlowNode for value
- line 231: ControlFlowNode for value
- line 225: ControlFlowNode for .0
- line 231: ControlFlowNode for file
- line 229: ControlFlowNode for Path()

---
