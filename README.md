# Password Strength Analyzer

A production-quality web application that analyzes the strength of a password in real time, provides an entropy score, detects common/breached passwords, and delivers actionable improvement suggestions.

Built with **Python (Flask)** on the backend and **HTML / CSS / JavaScript** on the frontend.

---

## Project Structure

```
PasswordStrengthAnalyzer/
│
├── frontend/
│   ├── index.html          # Main UI page
│   ├── style.css           # All visual styles and design tokens
│   └── script.js           # Client-side interactivity and API calls
│
├── backend/
│   ├── app.py              # Flask app — routes and entry point
│   ├── analyzer.py         # Core password analysis orchestrator
│   ├── dictionary_checker.py  # Common/breached password lookup
│   ├── entropy.py          # Information entropy calculator
│   ├── suggestions.py      # Human-readable improvement tips generator
│   ├── password_storage.py # Secure hashing utilities (bcrypt)
│   └── common_passwords.txt   # Reference word list (never user data)
│
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone <repository-url>
cd PasswordStrengthAnalyzer
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the development server

```bash
python backend/app.py
```

The application will be available at **http://127.0.0.1:5000**

---

## Module Responsibilities

| File | Responsibility |
|---|---|
| `app.py` | Flask entry point — registers routes, serves frontend |
| `analyzer.py` | Orchestrates all checks; returns a structured strength report |
| `dictionary_checker.py` | Loads `common_passwords.txt`; detects known-weak passwords |
| `entropy.py` | Calculates pool-based and Shannon entropy in bits |
| `suggestions.py` | Maps failed checks to prioritized improvement tips |
| `password_storage.py` | Hashes passwords with bcrypt; ensures no plaintext is stored |
| `common_passwords.txt` | Reference word list — NOT used to store user passwords |
| `index.html` | Semantic HTML shell with SEO meta tags |
| `style.css` | CSS design tokens, layout, components, and responsive styles |
| `script.js` | Input handling, Fetch API client, DOM rendering |

---

## Security Principles

> ⚠️ **Plaintext passwords are never stored.**
> Only bcrypt-hashed digests are persisted if analysis history is ever logged.

- All password hashing uses **bcrypt** with a minimum work factor of **12**.
- The `common_passwords.txt` file is a **read-only reference list** — it contains no user data.
- Raw password strings exist only in memory during a single request lifecycle.

---

## Development Roadmap

> **Current status:** Project scaffolding complete. Implementation begins in the next step.

- [x] Step 1 — Project initialization and file structure
- [ ] Step 2 — Implement core analysis logic (`analyzer.py`, `entropy.py`)
- [ ] Step 3 — Implement dictionary checker (`dictionary_checker.py`)
- [ ] Step 4 — Implement suggestions generator (`suggestions.py`)
- [ ] Step 5 — Implement Flask API endpoints (`app.py`)
- [ ] Step 6 — Implement frontend UI (input, strength meter, results panel)
- [ ] Step 7 — Connect frontend to backend via Fetch API (`script.js`)
- [ ] Step 8 — Add unit tests (pytest)
- [ ] Step 9 — Production hardening and deployment

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Flask 3.x |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Password Hashing | bcrypt |
| Testing | pytest |

---

## License

MIT License — see `LICENSE` for details.
