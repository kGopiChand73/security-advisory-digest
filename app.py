"""Streamlit UI for the Security Advisory Digest.

Run with:
    streamlit run app.py

Falls back to a CLI message if Streamlit isn't installed.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

# Ensure imports work when running from any cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import streamlit as st
except ImportError:
    print("Streamlit is not installed. Install with:")
    print("    pip install streamlit")
    print("Or run the CLI version instead:")
    print("    python -m src.main")
    sys.exit(1)

from src.llm_helper import active_provider
from src.processor import run_digest
from src.utils import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Security Advisory Digest",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Security Advisory Digest")
st.caption(
    "AI agent that turns noisy public security feeds into a focused, "
    "**only-what-affects-you** Markdown digest."
)

# ---------------------------------------------------------------------------
# Sidebar — configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Configuration")

    provider = st.selectbox(
        "LLM provider",
        options=["mock", "gemini", "openai"],
        index=["mock", "gemini", "openai"].index(active_provider())
        if active_provider() in ("mock", "gemini", "openai") else 0,
        help="`mock` is rule-based and offline. "
             "`gemini` and `openai` need an API key.",
    )
    os.environ["LLM_PROVIDER"] = provider

    if provider == "gemini":
        existing = os.getenv("GEMINI_API_KEY", "")
        key = st.text_input(
            "GEMINI_API_KEY",
            value=existing,
            type="password",
            help="Get a free key at https://aistudio.google.com/apikey",
        )
        if key:
            os.environ["GEMINI_API_KEY"] = key
    elif provider == "openai":
        existing = os.getenv("OPENAI_API_KEY", "")
        key = st.text_input("OPENAI_API_KEY", value=existing, type="password")
        if key:
            os.environ["OPENAI_API_KEY"] = key

    st.divider()

    max_per_feed = st.slider("Advisories per feed", 5, 100, 30, 5)
    top_k = st.slider("Top-K candidates per stack item", 1, 10, 3, 1)
    threshold = st.slider("Similarity threshold", 0.0, 1.0, 0.05, 0.01)

    st.divider()
    st.markdown(
        "**3 feeds:**\n"
        "- GitHub Security Advisories\n"
        "- NVD (NIST)\n"
        "- CISA KEV"
    )

# ---------------------------------------------------------------------------
# Main panel — stack input
# ---------------------------------------------------------------------------
st.subheader("1. Your tech stack")

uploaded = st.file_uploader(
    "Upload a stack.yaml (or use the default)",
    type=["yaml", "yml"],
    help="See data/sample_input.yaml for an example.",
)

stack_path = "stack.yaml"
if uploaded is not None:
    tmp = tempfile.NamedTemporaryFile(
        delete=False, suffix=".yaml", mode="wb")
    tmp.write(uploaded.getvalue())
    tmp.close()
    stack_path = tmp.name
    st.success(f"Using uploaded stack: {uploaded.name}")
else:
    if os.path.exists(stack_path):
        with open(stack_path, "r", encoding="utf-8") as f:
            with st.expander("Preview default stack.yaml", expanded=False):
                st.code(f.read(), language="yaml")
    else:
        st.warning("No stack.yaml found in the project root.")

# ---------------------------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------------------------
st.subheader("2. Run the digest")

run_btn = st.button("🚀 Generate digest", type="primary")

if run_btn:
    overrides = {
        "max_per_feed": max_per_feed,
        "top_k": top_k,
        "threshold": threshold,
        "stack_path": stack_path,
    }

    progress_box = st.empty()
    log_lines: list[str] = []

    def _progress(msg: str) -> None:
        log_lines.append(msg)
        progress_box.code("\n".join(log_lines), language="text")

    with st.spinner("Running pipeline (fetching, indexing, judging)..."):
        try:
            matches, out_path, stats = run_digest(
                overrides=overrides, progress=_progress)
        except Exception as e:  # noqa: BLE001
            st.error(f"Pipeline failed: {e}")
            st.stop()

    # -----------------------------------------------------------------------
    # 3 — Results
    # -----------------------------------------------------------------------
    st.subheader("3. Results")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Advisories scanned", stats["advisories"])
    col2.metric("Stack items", stats["stack_items"])
    col3.metric("Matches", stats["matches"])
    col4.metric("Provider", stats["provider"])

    if not matches:
        st.info("No advisories matched your stack today. Try lowering the "
                "similarity threshold or expanding stack.yaml.")
    else:
        # Show structured output table
        rows = []
        for m in matches:
            rows.append({
                "ID": m["advisory"].get("id"),
                "Severity": m["advisory"].get("severity"),
                "Stack item": (
                    f"{m['stack_item']['name']} "
                    f"{m['stack_item'].get('version', '')}"
                ).strip(),
                "Similarity": round(m["similarity"], 2),
                "Confidence": round(m["verdict"].confidence, 2),
                "Impact": m["verdict"].impact,
                "Action": m["verdict"].action,
                "Link": m["advisory"].get("url"),
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

    # -----------------------------------------------------------------------
    # 4 — Markdown digest preview + download
    # -----------------------------------------------------------------------
    st.subheader("4. Markdown digest")
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            md_text = f.read()
        with st.expander("Preview", expanded=True):
            st.markdown(md_text)
        st.download_button(
            label="⬇️ Download digest (.md)",
            data=md_text,
            file_name=os.path.basename(out_path),
            mime="text/markdown",
        )

    # JSON export (structured output requirement)
    json_payload = {
        "stats": stats,
        "matches": [
            {
                "stack_item": m["stack_item"],
                "advisory": m["advisory"],
                "similarity": m["similarity"],
                "verdict": m["verdict"].to_dict(),
            }
            for m in matches
        ],
    }
    st.download_button(
        label="⬇️ Download structured JSON",
        data=json.dumps(json_payload, indent=2, default=str),
        file_name="digest.json",
        mime="application/json",
    )
else:
    st.info("Configure the sidebar, optionally upload a custom stack.yaml, "
            "and click **Generate digest**.")

st.divider()
st.caption("Built for the AI Prototype Challenge — RAG over public "
           "advisory feeds + LLM impact judge.")
