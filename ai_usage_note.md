# AI Usage Note

This document records how AI assistance shaped this prototype: what
worked well, what didn't, and the prompts that produced the best
results.

## 1. Where AI helped

| Area | How AI helped |
|---|---|
| **Architecture** | Suggested the *fetch → embed → retrieve → judge → write* pipeline pattern up-front, which mapped cleanly to the challenge requirements. |
| **API integration** | Generated the initial scaffolding for GitHub / NVD / CISA fetchers (URLs, query params, response shapes). |
| **YAML parsing** | When PyPI was blocked on the corporate network, AI rewrote a tiny in-house YAML parser (~30 lines) so the project could keep working with **zero external dependencies**. |
| **Vector store** | When ChromaDB couldn't be installed, AI proposed an in-memory **TF-IDF cosine similarity** index that works for this PoC scale (≤ a few hundred advisories). |
| **Streamlit UI** | Generated the multi-section UI (sidebar config, file upload, metrics, dataframe, download buttons) in one pass. |
| **Tests** | Wrote happy-path tests for stack loading, vector store retrieval, the LLM judge, and the full end-to-end pipeline using offline fixtures. |
| **Documentation** | Drafted README, prompts.md, and this note structured around the challenge checklist. |

## 2. Where AI got things wrong

| Issue | What happened | How we fixed it |
|---|---|---|
| **False positives** | The mock LLM judge flags `python 3.11` as affected by *any* advisory mentioning the word "python" — including Rust-side PyO3 issues that don't affect CPython itself. | Switching `LLM_PROVIDER=gemini` largely fixes this; we documented the limitation. |
| **Network assumptions** | First version assumed `pip install requests` would work. Corporate proxy returned **HTTP 403** on PyPI. | We replaced `requests` with stdlib `urllib`, replaced `PyYAML` and `python-dotenv` with tiny in-house parsers, and removed `chromadb` / `sentence-transformers`. |
| **SSL inspection** | First version failed with `SSL: CERTIFICATE_VERIFY_FAILED` on a corporate network with TLS interception. | Added an `INSECURE_SSL=1` env-var fallback in `src/feeds/_http.py` that retries with an unverified context only if verified mode fails. |
| **Python 3.14 wheels** | When trying to install `chromadb`, no wheel existed for the freshly-released Python 3.14. | Removed the dependency entirely (TF-IDF replacement). |
| **CVSS field paths** | First NVD parser only looked for `cvssMetricV31`. Many older CVEs only have `cvssMetricV30` or `cvssMetricV2`. | Added a fallback chain across the three CVSS variants. |
| **Markdown sorting** | Initial sort didn't break ties cleanly; HIGH and MEDIUM entries appeared in mixed order. | Sort by `(severity_rank, -similarity)` — highest similarity first within each severity. |

## 3. Best prompts that gave good results

### Prompt #1 — High-quality LLM judge

> *"You are a senior security analyst. Given ONE security advisory and ONE tech-stack item, decide whether the advisory genuinely affects this stack item. **Be strict: if the advisory is about a different product that merely shares a keyword, answer false.** Respond ONLY with compact JSON matching this exact schema..."*

Why it worked: the **strict** instruction plus the **schema** in the
system prompt eliminated almost all keyword-only false positives in
testing.

### Prompt #2 — Force structured output

> *"Respond ONLY with compact JSON. No prose, no markdown fences, no explanations."*

Combined with the provider's native JSON mode
(`response_format=json_object` / `response_mime_type=application/json`),
this made parsing reliable. Even when the LLM occasionally added a
markdown code fence, our `_parse_json_verdict` helper strips it before
parsing.

### Prompt #3 — Architecture brainstorming

> *"Give me 3 alternative architectures for a security advisory digest with these constraints: ≥3 feeds, RAG matching against a YAML inventory, LLM judge, Markdown output. Score each on simplicity vs. accuracy."*

This produced the *fetch → embed → retrieve → judge → write* shape we
ended up using, plus two simpler/heavier alternatives we rejected.

## 4. Things AI couldn't do for us

- **Decide which 3 feeds to use** — that was a domain call.
- **Write a credible `stack.yaml`** — required knowing what our team
  actually uses.
- **Diagnose corporate-network failures** — we had to read the actual
  HTTP 403 / SSL errors and decide on the workarounds.
- **Replace human review** for the demo script and the rubric mapping
  in the README.

## 5. What we'd do differently next time

1. **Start with offline fixtures** before wiring live feeds — would have
   surfaced the network restrictions on day 1 instead of day 2.
2. **Pin Python version** in CI from the beginning (3.11 is the safest
   for ML libraries; 3.14 broke many wheels).
3. **Add a `--demo` mode** that injects guaranteed-match advisories so
   the digest is always populated for a recording.
4. **Cache feed responses** to a local JSON file so the same demo can
   be replayed without internet.
