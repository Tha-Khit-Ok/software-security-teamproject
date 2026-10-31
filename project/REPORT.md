# Term Project Report — Secure Build

> Fill in every section. Keep the headings. Total **100 pts** (see rubric at the end).
> This is **team work** (2–3). Do not share your report with other teams.

## Cover

| Field | Value |
|---|---|
| Team name | Tha-Khit-Ok (TEAM_ID: `Tha-Khit-Ok`) |
| Members (name + ID) | Athichon (6631503046), <Member 2>, <Member 3> |
| Target application | NoteVault (`project/starter-app`) |
| Repository URL | https://github.com/Tha-Khit-Ok/software-security-teamproject |
| Demo video (unlisted YouTube / Google Drive link) | |
| Date | 6 November 2026 |

## AI-tool usage disclosure
*Academic integrity: state how you used any AI tools (ChatGPT, Copilot, etc.) — e.g. searching, coding, translating, drafting. "None" is a valid answer.*

| Tool | How it was used |
|---|---|
| | |

---

## 1. Executive Summary
*(½ page) What the app is, how many findings by severity, and the overall risk before vs. after your fixes.*

---

## 2. System Scope & Function
- What the application does; in-scope components and endpoints.
- **Data-Flow Diagram (DFD):** processes, data stores, external entities, **trust boundaries** (insert image).

---

## 3. Threat Model — STRIDE  *(20 pts)*

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

*Then rank the top 5 risks by likelihood × impact.*

---

## 4. Vulnerability Findings  *(25 pts)*

### Finding F-01 — Mass Assignment in User Registration
| Field | Value |
|---|---|
| CWE | CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| OWASP 2025 | A01:2025 – Broken Access Control |
| Severity | High (CVSS 3.1: 8.8, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Location | `starter-app/app.py`, function `register()`, line 114 |
| Found by | Athichon (6631503046) |
| Reproduction | 1. Send POST request to `/register` with `username=hacker&password=1234&role=admin`.<br>2. Log in at `http://localhost:8080` as `hacker` / `1234`.<br>3. Observe the `admin` panel link is granted to the newly registered account. |
| Impact | Any unauthenticated attacker can self-assign the `admin` role during registration, achieving immediate privilege escalation and full administrative access. |
| Root Cause | The server blindly trusts the `role` parameter supplied in the request (`request.form.get("role")`) instead of enforcing `role = "user"` server-side. |
| Evidence | ![F-01 exploit](img/f01-exploit.png) |

---

### Finding F-02 — Weak Password Hashing Using Unsalted MD5
| Field | Value |
|---|---|
| CWE | CWE-916: Use of Password Hash With Insufficient Computational Effort (CWE-328: Use of Weak Hash) |
| OWASP 2025 | A04:2025 – Cryptographic Failures |
| Severity | High (CVSS 3.1: 7.5, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| Location | `starter-app/app.py`, functions `seed()` (lines 68–69), `register()` (line 117), and `login()` (line 129) |
| Found by | Athichon (6631503046) |
| Reproduction | 1. View the user database via `/admin` to obtain the 32-character hex MD5 hashes (`0192023a7bbd73250516f069df18b500` for `admin`, `81dc9bdb52d04dc20036dbd8313ed055` for `hacker`).<br>2. Query the hashes against a standard MD5 rainbow table (CrackStation), recovering plaintext passwords `admin123` and `1234` in under 1 second. |
| Impact | Any database leak (via SQL Injection or `/admin` exposure) allows immediate offline reversal of all user and administrator passwords. |
| Root Cause | Passwords are hashed using unsalted `hashlib.md5()` with zero work factor instead of a salted, adaptive password hashing algorithm (e.g., PBKDF2/scrypt via Werkzeug). |
| Evidence | ![F-02 MD5 hashes](img/f02-exploit.png)<br>![F-02 cracked MD5](img/f02-cracked.png) |

---

### Finding F-03 — Session Cookie Missing HttpOnly, Secure, and SameSite Flags
| Field | Value |
|---|---|
| CWE | CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag / CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| OWASP 2025 | A02:2025 – Security Misconfiguration |
| Severity | Medium (CVSS 3.1: 6.5, AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N) |
| Location | `starter-app/app.py`, function `login()`, line 136 |
| Found by | Athichon (6631503046) |
| Reproduction | 1. Log in to `http://localhost:8080`.<br>2. Open Browser DevTools (`F12`) → **Application** → **Cookies** → `http://localhost:8080`.<br>3. Observe that `HttpOnly`, `Secure`, and `SameSite` columns for the `session` cookie are empty, and `document.cookie` exposes the raw JWT in the browser console. |
| Impact | Attackers exploiting Stored XSS in notes can steal session tokens via `document.cookie`, and missing `SameSite`/`Secure` flags leave sessions vulnerable to CSRF and network sniffing. |
| Root Cause | `resp.set_cookie("session", tok)` is called without `httponly=True`, `secure=True`, or `samesite="Lax"`. |
| Evidence | ![F-03 insecure cookie flags](img/f03-exploit.png) |

---

### Finding F-04 — Hard-coded JWT Secret Key and Insecure JWT Algorithm Whitelist
| Field | Value |
|---|---|
| CWE | CWE-798: Use of Hard-coded Credentials / CWE-347: Improper Verification of Cryptographic Signature |
| OWASP 2025 | A04:2025 – Cryptographic Failures / A08:2025 – Software or Data Integrity Failures |
| Severity | Critical (CVSS 3.1: 9.8, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Location | `starter-app/app.py`, line 23 (`SECRET = "notevault-dev-secret"`), `Dockerfile` line 5, and `current_user()` line 83 |
| Found by | Athichon (6631503046) |
| Reproduction | 1. Extract the hardcoded secret `"notevault-dev-secret"` from `app.py` line 23.<br>2. Forge an admin token: `jwt.encode({"sub": "admin"}, "notevault-dev-secret", algorithm="HS256")` → `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.KQ58cR1p-ax-civd998Zmx9iBJfg6zIuo5WLIj7yfJY`.<br>3. Replace the `session` cookie value in DevTools with the forged token and refresh `/`.<br>4. Result: Authenticated as `admin` without a password, exposing admin notes (`team=Tha-Khit-Ok marker=1eae94811e50`). *(Note: `current_user()` also includes `"none"` in `algorithms=["HS256", "none"]`; while PyJWT 1.7.1 blocks `alg="none"` when the key string is non-empty, listing `"none"` violates CWE-347 and must be removed).* |
| Impact | Complete authentication bypass; an attacker can forge valid session tokens for any user including `admin` and read all sensitive notes. |
| Root Cause | Cryptographic signing secret is hardcoded in source code instead of loaded from an environment variable, and `jwt.decode()` includes `"none"` in its algorithm whitelist. |
| Evidence | ![F-04 forged JWT admin session](img/f04-exploit.png) |

---

## 5. Remediation  *(25 pts)*

### Fix for F-01 — Mass Assignment in User Registration
| Field | Value |
|---|---|
| Commit | `70067c5` — `fix(F-01): prevent mass assignment in register by enforcing user role (CWE-915)` |
| Fixed by | Athichon (6631503046) |

**Before**
```python
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username") or (request.json or {}).get("username")
    password = request.form.get("password") or (request.json or {}).get("password")
    role = request.form.get("role") or (request.json or {}).get("role") or "user"
```

**After**
```python
@app.route("/register", methods=["POST"])
def register():
    req_json = request.get_json(silent=True) or {}
    username = request.form.get("username") or req_json.get("username")
    password = request.form.get("password") or req_json.get("password")
    role = "user"
```
- **Why this fixes it:** The server ignores any client-supplied `role` field and strictly assigns `"user"` to all newly registered accounts.
- **Why this approach (and not another):** Blocklisting specific role strings like `"admin"` is brittle if new privileged roles are introduced later; hardcoding the least-privileged role (`"user"`) on self-registration eliminates mass assignment completely.
- **Verification:** Repeating the POST request to `/register` with `role=admin` creates an account with `role="user"`, and accessing `/admin` returns `403 Forbidden`.
- **Proof the exploit now fails:** ![F-01 after fix](img/f01-fixed.png)

---

### Fix for F-02 — Weak Password Hashing Using Unsalted MD5
| Field | Value |
|---|---|
| Commit | `3183ca6` — `fix(F-02): replace md5 with werkzeug password hashing (CWE-916)` |
| Fixed by | Athichon (6631503046) |

**Before**
```python
# In seed() / register() / login():
hashlib.md5(password.encode()).hexdigest()
```

**After**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# In seed() and register():
generate_password_hash(password)

# In login():
if not row or not check_password_hash(row["password"], password or ""):
    return "login failed", 401
```
- **Why this fixes it:** `generate_password_hash` automatically generates a unique cryptographic salt per user and applies key-stretching (PBKDF2-HMAC-SHA256 / scrypt), making precomputed rainbow tables useless and slowing down brute-force attacks by orders of magnitude.
- **Why this approach (and not another):** Using Werkzeug's built-in password hashing requires no additional external dependencies, handles salt generation and constant-time comparison (`check_password_hash`) safely out of the box.
- **Verification:** Inspecting user records shows salted PBKDF2/scrypt password hashes instead of 32-char MD5 hashes.
- **Proof the exploit now fails:** ![F-02 after fix](img/f02-fixed.png)

---

### Fix for F-03 — Session Cookie Missing HttpOnly, Secure, and SameSite Flags
| Field | Value |
|---|---|
| Commit | `00142ca` — `fix(F-03): set httponly, secure, and samesite flags on session cookie (CWE-1004)` |
| Fixed by | Athichon (6631503046) |

**Before**
```python
resp = make_response(redirect("/"))
resp.set_cookie("session", tok)
```

**After**
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
...
resp = make_response(redirect("/"))
resp.set_cookie("session", tok, httponly=True, secure=True, samesite="Lax")
```
- **Why this fixes it:** `httponly=True` prevents client-side scripts (`document.cookie`) from accessing the session token during an XSS attack; `secure=True` restricts transmission to secure contexts; `samesite="Lax"` mitigates Cross-Site Request Forgery (CSRF).
- **Verification:** Inspecting Browser DevTools → Application → Cookies after login confirms `HttpOnly ✓`, `Secure ✓`, and `SameSite = Lax`.
- **Proof the exploit now fails:** ![F-03 after fix](img/f03-fixed.png)

---

### Fix for F-04 — Hard-coded JWT Secret Key and Insecure JWT Algorithm Whitelist
| Field | Value |
|---|---|
| Commit | `560089e` — `fix(F-04): load jwt secret from env var and disallow none algorithm (CWE-798, CWE-347)` |
| Fixed by | Athichon (6631503046) |

**Before**
```python
SECRET = "notevault-dev-secret"  # used to sign session tokens
...
data = jwt.decode(tok, SECRET, algorithms=["HS256", "none"])
```

**After**
```python
SECRET = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
...
data = jwt.decode(tok, SECRET, algorithms=["HS256"])
```
- **Why this fixes it:** The signing secret is loaded from an environment variable (with a cryptographically random 256-bit fallback via `os.urandom(32).hex()` rather than a static string literal), and `jwt.decode` strictly enforces `algorithms=["HS256"]`, rejecting unsigned (`"none"`) or forged tokens signed with `"notevault-dev-secret"`.
- **Verification:** Setting the `session` cookie to the previously forged admin token (`eyJ0eXAiOiJKV1Qi...`) no longer authenticates as `admin`; the user remains unauthenticated.
- **Proof the exploit now fails:** ![F-04 after fix](img/f04-fixed.png)

---

## 6. Supply-Chain Hardening  *(15 pts)*
- **SBOM** (CycloneDX) generated — attach `sbom.json`, note component count.
- **Artifact signed & verified** with Cosign — paste the `cosign verify` output.
- One-paragraph **SLSA** self-assessment (which level, why).

---

## 7. Security CI Pipeline  *(10 pts)*
- Link to the GitHub Actions workflow (SAST + SCA + secret scanning).
- Screenshot of a build **failing** on a HIGH/CRITICAL finding.
- How the gate is configured (what fails the build).

---

## 8. Conclusion & Reflection  *(5 pts — clarity)*
- Residual risks and what you'd harden next.
- Lessons learned.

---

## Appendix
- Tools used, references (OWASP/CWE links), and the team's task split.

---

## Grading rubric (100)

| Criterion | Pts |
|---|---|
| Threat model quality & completeness (§3) | 20 |
| Vulnerability findings — correctness, CWE/OWASP mapping, depth (§4) | 25 |
| Remediation quality — correct, minimal, well-explained (§5) | 25 |
| Supply-chain hardening — SBOM + signing + provenance (§6) | 15 |
| CI pipeline — works, fails build appropriately (§7) | 10 |
| Presentation & report clarity (§1, §8) | 5 |

*All work stays within the [ethics policy](../ETHICS.md).*
