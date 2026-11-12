# 🛡️ AI Code Security & Algorithm Auditor Hub

A Streamlit web app that uses Google Gemini (via the official `google-genai` SDK) to audit source code for security flaws, analyse algorithm complexity, and answer questions about your code.

## Features

| Tab | What it does |
| --- | --- |
| 🛡️ Vulnerability & Security Scanner | Scans C++ / Python code for buffer overflows, memory leaks, uninitialised pointers, unsafe functions, injection risks and more. Results are filtered by the severity you choose. |
| ⚡ Complexity Analyzer | Breaks down best / average / worst-case time complexity and space complexity, then suggests optimisations. |
| 💬 Code Q&A & Debugger | Chat about the loaded code, trace execution step by step, or request bug fixes. |

**Sidebar:** target language (`C++`, `Python`, `General`), minimum severity (`Low`, `Medium`, `High`, `Critical Security Flaws`), export audit report as `.txt`, clear session.

**Input:** upload `.cpp`, `.py`, `.txt` files (multiple allowed) and/or paste code directly.

## Reliability and safety design

- **Retry with backoff:** every model call goes through `call_gemini_safe` (3 attempts, `2 * attempt` second delay) and only retries transient errors (503, 429, 5xx, timeouts, connection problems).
- **Missing secret handling:** if `GEMINI_API_KEY` is absent, the app shows a clear error and stops instead of crashing.
- **Empty input checks:** friendly warnings if no code is provided.
- **Large input protection:** code is trimmed to the first 20,000 characters, and the app tells you when that happens.
- **Isolated error cards:** each tab has its own `try/except`, so one failure does not break the session.
- **Prompt-injection defence:** your code is sent as untrusted data inside delimiter tags, and the model is told never to obey instructions found in it.

## Project structure

```
.
├── app.py
├── requirements.txt
└── README.md
```

## Run locally

```bash
pip install -r requirements.txt
```

Create `.streamlit/secrets.toml` (do **not** commit this file):

```toml
GEMINI_API_KEY = "your-api-key-here"
```

Then start the app:

```bash
streamlit run app.py
```

## Deploy

1. **Push to GitHub:** create a new repository, then use *Add file → Upload files* to add `app.py`, `requirements.txt` and `README.md`, and commit.
2. **Deploy on Streamlit Community Cloud:** go to [share.streamlit.io](https://share.streamlit.io), click *Create app*, select your repository and branch, and set the main file to `app.py`.
3. **Add the secret:** open *Advanced settings → Secrets* (or *App settings → Secrets* after deploying) and paste:
   ```toml
   GEMINI_API_KEY = "your-api-key-here"
   ```
4. Click *Deploy*.

Get an API key from [Google AI Studio](https://aistudio.google.com/).

## Configuration

At the top of `app.py`:

| Constant | Default | Purpose |
| --- | --- | --- |
| `MODEL_NAME` | `gemini-3.8-flash` | Gemini model used for all analysis |
| `MAX_CODE_CHARS` | `20000` | Maximum characters of code sent to the model |
| `MAX_RETRIES` | `3` | Attempts per model call |
| `MAX_CHAT_TURNS` | `12` | Chat turns sent back as context |

## Troubleshooting

| Problem | Fix |
| --- | --- |
| "API key missing" banner | Add `GEMINI_API_KEY` to Streamlit secrets and reboot the app. |
| "Model was not found" | Check that `MODEL_NAME` is a model your API key can access. |
| "Rate limit or quota reached" | Wait and retry, or check your quota in Google AI Studio. |
| "High demand" error after retries | The model is overloaded; try again in a minute. |
| Large file seems partially analysed | Only the first 20,000 characters are sent. Split the file or paste the relevant part. |

## Limitations

- AI output can contain false positives and miss real vulnerabilities. Treat results as a first-pass review, not a certified security audit.
- Static analysis only: the app never compiles or runs your code.
- Do not paste secrets or proprietary code you are not allowed to send to a third-party API.

## Tech stack

Python · Streamlit · google-genai · Gemini
