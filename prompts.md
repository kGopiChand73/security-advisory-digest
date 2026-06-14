# Prompts used by the LLM Judge

The LLM acts as a **judge** that decides, given one stack item and one
candidate advisory, whether the advisory truly affects the stack item.

It is required to return **strict JSON** so the rest of the pipeline can
filter, sort, and render the results deterministically.

The same prompts are used for **Gemini** and **OpenAI** providers. For
the offline `mock` provider, a rule-based heuristic stands in.

---

## System prompt

```
You are a senior security analyst. Given ONE security advisory and ONE
tech-stack item, decide whether the advisory genuinely affects this
stack item. Be strict: if the advisory is about a different product
that merely shares a keyword, answer false.
Respond ONLY with compact JSON matching this exact schema:
{"affects": true|false, "impact": "<one short sentence>", "action": "<one short remediation>", "confidence": 0.0-1.0}.
```

### Why strict?

- **Strict mode** — explicitly told to reject keyword-only matches
  (e.g. *"Python"* keyword in a PyO3-Rust advisory).
- **Compact JSON** — easy to parse with `json.loads`.
- **Fixed schema** — `affects` (bool), `impact` (str), `action` (str),
  `confidence` (float 0–1).
- **No prose around JSON** — keeps `response_format=json_object` happy.

---

## User prompt template

```
Stack item:
  name: <stack name>
  version: <stack version>
  category: <languages|frameworks|infrastructure|libraries>

Advisory:
  id: <CVE / GHSA id>
  source: <github|nvd|cisa>
  severity: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN>
  affected: <product list, comma-separated>
  title: <advisory title>
  description: <advisory body, truncated to 1000 chars>
```

---

## Example call & response

**Input (user prompt filled in):**
```
Stack item:
  name: log4j
  version: 2.20
  category: libraries

Advisory:
  id: CVE-2021-44228
  source: nvd
  severity: CRITICAL
  affected: log4j-core, apache
  title: Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints
  description: Apache Log4j2 versions 2.0-beta9 through 2.15.0 ...
```

**Expected response:**
```json
{
  "affects": true,
  "impact": "log4j 2.20 is within the vulnerable range; remote code execution possible.",
  "action": "Upgrade log4j-core to 2.17.1 or later immediately.",
  "confidence": 0.95
}
```

---

## Negative-case example

**Input:**
```
Stack item:
  name: django
  version: 4.2
  category: frameworks

Advisory:
  id: CVE-2024-9999
  source: nvd
  severity: MEDIUM
  affected: wordpress
  title: WordPress plugin XSS vulnerability
  description: XSS in a WordPress plugin ...
```

**Expected response:**
```json
{
  "affects": false,
  "impact": "Advisory is for WordPress, unrelated to Django.",
  "action": "No action needed for this stack item.",
  "confidence": 0.9
}
```

---

## Provider-specific notes

| Provider | Model used | JSON mode |
|---|---|---|
| Gemini   | `gemini-1.5-flash`   | `response_mime_type="application/json"` |
| OpenAI   | `gpt-4o-mini`        | `response_format={"type":"json_object"}` |
| mock     | rule-based fallback  | n/a |

If the chosen provider fails (network error, missing key, malformed
JSON), the pipeline **gracefully falls back to mock** so the digest is
always produced.

---

## Failure handling

If the LLM returns text that isn't valid JSON, `_parse_json_verdict`
strips Markdown code-fences and retries. If parsing still fails, the
provider returns `None` and the dispatcher falls back to the mock judge
for that single match (the rest of the pipeline is unaffected).

---

## Future improvements

- Few-shot examples in the system prompt to improve precision.
- Pass the **full CVE description** (not truncated) when token budget allows.
- Ask for **CVSS-style impact summary** (Confidentiality / Integrity /
  Availability) instead of free text.
- Add a follow-up prompt asking for **patched-version** extraction so
  the digest can show "Upgrade to X.Y.Z" automatically.
