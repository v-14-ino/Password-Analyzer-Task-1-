/**
 * script.js — Frontend JavaScript for Password Strength Analyzer
 * ---------------------------------------------------------------
 * UI Redesign Update
 *
 * Responsibilities:
 *   1. INITIALIZATION     — Query DOM elements once the page is ready.
 *   2. TOGGLE HANDLER     — Show/hide password eye icon.
 *   3. INPUT HANDLER      — Intercept form submit, prevent page refresh.
 *   4. API CLIENT         — POST password to /analyze via fetch().
 *   5. UI RENDERERS       — Build the redesigned result panels:
 *        renderStrengthCard()      — Module 6 real score/classification
 *        renderPolicyPanel()       — unified Password Policy Analysis (Mod 2+3)
 *        renderDictionaryCheck()   — Module 4 dictionary attack detection
 *        renderSuggestions()       — actionable improvement tips
 *   6. HELPERS            — clearUI, showError, setLoadingState
 *
 * Backend contract (Module 6 — unchanged transport, extended response):
 *   POST /analyze → {
 *     "length_check": {
 *       "length", "minimum_required", "recommended_length", "passed", "message"
 *     },
 *     "character_diversity": {
 *       "uppercase", "lowercase", "numbers", "special_characters"
 *     },
 *     "strength": {
 *       "score", "classification", "progress"
 *     }
 *   }
 */


/* ============================================================
   CONSTANTS
   ============================================================ */

/** Base URL for all backend API calls. */
const API_BASE = 'http://127.0.0.1:5000';

/** POST endpoint for password analysis. */
const ANALYZE_ENDPOINT = `${API_BASE}/analyze`;


/* ============================================================
   1. INITIALIZATION — DOM READY
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {

  // ── Query DOM elements ─────────────────────────────────────────────────────

  /** The <form> element. */
  const form            = document.getElementById('analyzer-form');

  /** The password <input> field. */
  const passwordInput   = document.getElementById('password-input');

  /** The show/hide eye toggle <button>. */
  const toggleBtn       = document.getElementById('toggle-visibility');

  /** The submit <button>. */
  const analyzeBtn      = document.getElementById('analyze-btn');

  /** The unified results wrapper. Hidden until first response. */
  const resultsArea     = document.getElementById('results-area');

  /** The strength card section (placeholder). */
  const strengthRating  = document.getElementById('strength-rating');
  const strengthScore   = document.getElementById('strength-score');
  const strengthPips    = document.getElementById('strength-pips');

  /** Policy output div — script injects .policy-row elements here. */
  const policyOutput    = document.getElementById('policy-output');

  /** Dictionary check output div — script injects .dict-result here. */
  const dictionaryOutput = document.getElementById('dictionary-output');

  /** Entropy output div — script injects .entropy-container here. */
  const entropyOutput   = document.getElementById('entropy-output');

  /** Crack time output div — script injects .crack-time-card here. */
  const crackTimeOutput = document.getElementById('crack-time-output');

  /** Suggestions list — script injects <li> elements here. */
  const suggestionsOutput = document.getElementById('suggestions-output');

  /** Error paragraph. Hidden by default. */
  const errorMessage    = document.getElementById('error-message');

  /** Generator Action elements */
  const generatePwBtn   = document.getElementById('generate-pw-btn');
  const copyPwBtn       = document.getElementById('copy-pw-btn');
  const copyStatusMsg   = document.getElementById('copy-status-msg');


  // ── Attach event listeners ────────────────────────────────────────────────

  form.addEventListener('submit', handleSubmit);
  toggleBtn.addEventListener('click', handleToggleVisibility);
  generatePwBtn.addEventListener('click', handleGeneratePassword);
  copyPwBtn.addEventListener('click', handleCopyPassword);


  /* ==========================================================================
     2. TOGGLE HANDLER — handleToggleVisibility
     ==========================================================================
     Switches the password input between type="password" and type="text".
     Also flips the aria attributes and the CSS data attribute that swaps
     which SVG eye icon is visible.
     ========================================================================== */

  /**
   * Toggles the password field between masked and plain text.
   */
  function handleToggleVisibility() {
    const isHidden = passwordInput.type === 'password';

    // Flip the input type
    passwordInput.type = isHidden ? 'text' : 'password';

    // CSS uses data-visible on the INPUT to swap SVG icons
    passwordInput.setAttribute('data-visible', isHidden ? 'true' : 'false');

    // Keep aria attributes in sync
    toggleBtn.setAttribute('aria-label',   isHidden ? 'Hide password' : 'Show password');
    toggleBtn.setAttribute('aria-pressed', isHidden ? 'true' : 'false');
  }


  /* ==========================================================================
     2b. GENERATOR HANDLERS
     ========================================================================== */

  /**
   * Requests a cryptographically secure random password from the backend,
   * and fills the input field.
   */
  async function handleGeneratePassword() {
    setLoadingState(analyzeBtn, true);
    generatePwBtn.disabled = true;

    try {
      const response = await fetch(`${API_BASE}/generate`);
      if (!response.ok) {
        showError(errorMessage, `Failed to generate secure password: HTTP ${response.status}`);
        return;
      }
      const data = await response.json();
      
      // Clear previous results to avoid showing outdated results for the newly generated password
      clearUI(resultsArea, policyOutput, dictionaryOutput, entropyOutput, crackTimeOutput, suggestionsOutput, errorMessage);

      // Fill the password input automatically
      passwordInput.value = data.password;

    } catch (networkError) {
      showError(errorMessage, `Could not reach the server to generate password. (${networkError.message})`);
    } finally {
      generatePwBtn.disabled = false;
      setLoadingState(analyzeBtn, false);
    }
  }

  /**
   * Copies the generated password to the clipboard and displays a temporary feedback message.
   */
  async function handleCopyPassword() {
    const password = passwordInput.value;
    if (!password) {
      return;
    }

    let success = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(password);
        success = true;
      } catch (err) {
        console.warn('Navigator clipboard failed, falling back...', err);
      }
    }

    if (!success) {
      const textArea = document.createElement("textarea");
      textArea.value = password;
      textArea.style.position = "fixed";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        success = true;
      } catch (err) {
        console.error('Fallback copy failed:', err);
      }
      document.body.removeChild(textArea);
    }

    if (success) {
      copyStatusMsg.removeAttribute('hidden');
      setTimeout(() => {
        copyStatusMsg.setAttribute('hidden', '');
      }, 2000);
    }
  }


  /* ==========================================================================
     3. INPUT HANDLER — handleSubmit
     ==========================================================================
     Fires when the user clicks "Analyze Password" or presses Enter.
     ========================================================================== */

  /**
   * @param {SubmitEvent} event
   */
  async function handleSubmit(event) {
    event.preventDefault();

    const password = passwordInput.value;

    // Clear all previous results + error
    clearUI(resultsArea, policyOutput, dictionaryOutput, entropyOutput, crackTimeOutput, suggestionsOutput, errorMessage);

    // POST to backend
    await sendPasswordToBackend(password);
  }


  /* ==========================================================================
     4. API CLIENT — sendPasswordToBackend
     ==========================================================================
     Sends { "password": "..." } to POST /analyze.
     On success: delegates to the four render functions.
     On error: shows the error message panel.
     ========================================================================== */

  /**
   * @param {string} password - Raw password from the input field.
   */
  async function sendPasswordToBackend(password) {

    setLoadingState(analyzeBtn, true);

    try {
      const response = await fetch(ANALYZE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });

      if (!response.ok) {
        showError(
          errorMessage,
          `Server error: HTTP ${response.status} ${response.statusText}`
        );
        return;
      }

      const data = await response.json();

      // ── Render all sections ──────────────────────────────────────────────
      renderStrengthCard(strengthRating, strengthScore, strengthPips, data.strength);
      renderPolicyPanel(policyOutput, data.length_check, data.character_diversity);
      renderDictionaryCheck(dictionaryOutput, data.dictionary_check);
      renderEntropy(entropyOutput, data.entropy);
      renderCrackTime(crackTimeOutput, data.crack_time);
      renderSuggestions(suggestionsOutput, data.length_check, data.character_diversity);
      revealResultsArea(resultsArea);

    } catch (networkError) {
      showError(
        errorMessage,
        `Could not reach the server. Is Flask running on port 5000?\n(${networkError.message})`
      );
    } finally {
      setLoadingState(analyzeBtn, false);
    }
  }


  /* ==========================================================================
     5a. UI RENDERER — renderStrengthCard  (Module 6)
     ==========================================================================
     Renders the real strength score returned by /analyze into the card.

     Pip level mapping (1 pip = weakest, 5 pips = strongest):
       "Weak"        → level 1  (red-rose)
       "Medium"      → level 2  (orange)
       "Fair"        → level 3  (amber)   — future band
       "Strong"      → level 4  (emerald)
       "Very Strong" → level 5  (violet)

     Rating text color is set via CSS variable names so it inherits
     the same tokens defined in style.css.
     ========================================================================== */

  /**
   * Maps a classification string to a pip level (1–5) and CSS color.
   *
   * @param {string} classification - One of: Weak, Medium, Strong, Very Strong.
   * @returns {{ level: number, color: string }}
   */
  function _classificationMeta(classification) {
    const map = {
      'Weak'        : { level: 1, color: 'var(--color-strength-1)' },
      'Medium'      : { level: 2, color: 'var(--color-strength-2)' },
      'Strong'      : { level: 4, color: 'var(--color-strength-4)' },
      'Very Strong' : { level: 5, color: 'var(--color-strength-5)' },
    };
    return map[classification] ?? { level: 0, color: 'var(--color-text-muted)' };
  }

  /**
   * Renders the strength card with real score data from the backend.
   *
   * @param {HTMLElement} ratingEl - The .strength-rating <p>.
   * @param {HTMLElement} scoreEl  - The .strength-score <p>.
   * @param {HTMLElement} pipsEl   - The .strength-pips <div>.
   * @param {Object}      data     - The 'strength' object from /analyze.
   *                                 { score, classification, progress }
   */
  function renderStrengthCard(ratingEl, scoreEl, pipsEl, data) {
    const meta = _classificationMeta(data.classification);

    // ── Rating label ──────────────────────────────────────────────────────────
    ratingEl.textContent = data.classification;
    ratingEl.style.color = meta.color;

    // ── Score text ───────────────────────────────────────────────────────────
    scoreEl.textContent = `${data.score} / 100`;

    // ── Pip level (CSS data attribute drives the fill via style.css) ────────
    pipsEl.setAttribute('data-level', String(meta.level));
  }


  /* ==========================================================================
     5b. UI RENDERER — renderPolicyPanel
     ==========================================================================
     Builds the unified "Password Policy Analysis" section by combining:
       - Module 2 length checks  (min length + recommended length)
       - Module 3 diversity checks (uppercase / lowercase / numbers / special)

     Layout produced (2-col grid on ≥480px, 1-col on mobile):
       ┌──────────────────────┬──────────────────────┐
       │ ✔  Minimum Length    │ ✔  Recommended Length │  ← full-width if needed
       ├──────────────────────┼──────────────────────┤
       │ ✔  Uppercase         │ ✔  Lowercase          │
       ├──────────────────────┼──────────────────────┤
       │ ✖  Number            │ ✔  Special Character  │
       └──────────────────────┴──────────────────────┘
       ╌╌╌ length message ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌

     Three visual states for length rows:
       --pass  length ≥ recommended
       --warn  length ≥ minimum but < recommended
       --fail  length < minimum
     ========================================================================== */

  /**
   * Builds and injects policy check rows into the policy grid.
   *
   * @param {HTMLElement} output     - The .policy-grid container.
   * @param {Object}      lengthData - data.length_check from /analyze.
   * @param {Object}      diversity  - data.character_diversity from /analyze.
   */
  function renderPolicyPanel(output, lengthData, diversity) {

    // ── Determine length row states ────────────────────────────────────────
    const minPassed  = lengthData.passed;
    const recPassed  = lengthData.length >= lengthData.recommended_length;

    // Min length: pass or fail
    const minState   = minPassed  ? 'pass' : 'fail';
    // Recommended: pass, warn (met min but not rec), or fail (didn't even meet min)
    const recState   = recPassed  ? 'pass' : (minPassed ? 'warn' : 'fail');

    // ── Build all six policy rows ──────────────────────────────────────────
    const rows = [
      _buildPolicyRow('Minimum Length (8+)',      minState,                            true),
      _buildPolicyRow('Recommended Length (12+)', recState,                            true),
      _buildPolicyRow('Uppercase Letter',          diversity.uppercase     ? 'pass' : 'fail', false),
      _buildPolicyRow('Lowercase Letter',          diversity.lowercase     ? 'pass' : 'fail', false),
      _buildPolicyRow('Number',                    diversity.numbers       ? 'pass' : 'fail', false),
      _buildPolicyRow('Special Character',         diversity.special_characters ? 'pass' : 'fail', false),
    ];

    // Append the length advisory message below the grid
    const msgClass = minPassed ? (recPassed ? 'pass' : 'warn') : 'fail';
    const message = `<p class="policy-message policy-message--${msgClass}">${lengthData.message}</p>`;

    output.innerHTML = rows.join('') + message;
  }


  /**
   * Returns the HTML string for one policy check row.
   *
   * @param {string}  label    - Human-readable policy name.
   * @param {string}  state    - 'pass' | 'warn' | 'fail'
   * @param {boolean} fullWidth - If true, spans both grid columns.
   * @returns {string} HTML string for a .policy-row element.
   */
  function _buildPolicyRow(label, state, fullWidth) {
    const icon      = state === 'pass' ? '✔' : (state === 'warn' ? '◐' : '✖');
    const chip      = state === 'pass' ? 'PASS' : (state === 'warn' ? 'WARN' : 'FAIL');
    const fullClass = fullWidth ? ' policy-row--full' : '';

    return `
      <div class="policy-row policy-row--${state}${fullClass}">
        <span class="policy-row__icon" aria-hidden="true">${icon}</span>
        <span class="policy-row__label">${label}</span>
        <span class="policy-chip">${chip}</span>
      </div>
    `;
  }


  /* ==========================================================================
     5c. UI RENDERER — renderSuggestions
     ==========================================================================
     Generates a prioritised list of actionable improvement suggestions
     based on which policy checks failed.

     Suggestion priority (top = most impactful):
       1. Too short (hard minimum not met)
       2. Not recommended length
       3. Missing uppercase
       4. Missing lowercase
       5. Missing numbers
       6. Missing special characters

     If no suggestions are needed, shows a "you're all good" message.
     ========================================================================== */

  /**
   * Builds and injects suggestion items into the suggestions list.
   *
   * @param {HTMLElement} output     - The <ul> suggestions list.
   * @param {Object}      lengthData - data.length_check from /analyze.
   * @param {Object}      diversity  - data.character_diversity from /analyze.
   */
  function renderSuggestions(output, lengthData, diversity) {

    const suggestions = [];

    // ── Length suggestions ─────────────────────────────────────────────────
    if (!lengthData.passed) {
      const shortage = lengthData.minimum_required - lengthData.length;
      suggestions.push(
        `Password is too short. Add at least ${shortage} more character${shortage > 1 ? 's' : ''} to reach the 8-character minimum.`
      );
    } else if (lengthData.length < lengthData.recommended_length) {
      suggestions.push(
        `Increase your password length to ${lengthData.recommended_length}+ characters for better security.`
      );
    }

    // ── Character diversity suggestions ───────────────────────────────────
    if (!diversity.uppercase) {
      suggestions.push('Add at least one uppercase letter (A–Z) to increase variety.');
    }
    if (!diversity.lowercase) {
      suggestions.push('Add at least one lowercase letter (a–z).');
    }
    if (!diversity.numbers) {
      suggestions.push('Include at least one number (0–9).');
    }
    if (!diversity.special_characters) {
      suggestions.push('Add a special character such as @, #, $, !, or % to greatly increase strength.');
    }

    // ── Render ─────────────────────────────────────────────────────────────
    if (suggestions.length === 0) {
      // All checks passed — show "all good" state
      output.innerHTML = `
        <li class="suggestions-empty">
          ✔ &nbsp;Your password meets all policy requirements. Great work!
        </li>
      `;
    } else {
      output.innerHTML = suggestions
        .map(s => `<li class="suggestion-item">${s}</li>`)
        .join('');
    }
  }


  /* ==========================================================================
     5d. HELPER — revealResultsArea
     ==========================================================================
     Removes the 'hidden' attribute from the results area so all result
     sections appear simultaneously (no staggered section reveals).
     ========================================================================== */

  /**
   * @param {HTMLElement} area - The #results-area wrapper.
   */
  function revealResultsArea(area) {
    area.removeAttribute('hidden');
  }


  /* ==========================================================================
     5e. UI RENDERER — renderDictionaryCheck  (Module 4)
     ==========================================================================
     Builds the Dictionary Attack Check card from data.dictionary_check.

     Two visual states:
       Pass — password NOT in common list
             .dict-result--pass, icon='✔', label='Not Found in Common Password Database'
       Fail — password IS in common list
             .dict-result--fail, icon='✖', label='Common Password Detected'
             + a .dict-result__match chip showing the matched entry

     Both states show the backend message below the status label.
     ========================================================================== */

  /**
   * Renders the dictionary attack check result card.
   *
   * @param {HTMLElement} output - The #dictionary-output container div.
   * @param {Object}      data   - The 'dictionary_check' object from /analyze.
   *                               { is_common: bool, matched_word: string|null, message: string }
   */
  function renderDictionaryCheck(output, data) {
    const isCommon = data.is_common;
    const state    = isCommon ? 'fail' : 'pass';
    const icon     = isCommon ? '✖' : '✔';
    const label    = isCommon
      ? 'Common Password Detected'
      : 'Not Found in Common Password Database';

    // Build the matched-word chip (only shown when is_common=true)
    const matchChip = isCommon && data.matched_word
      ? `<span class="dict-result__match" aria-label="Matched entry: ${data.matched_word}">
           Matched: ${data.matched_word}
         </span>`
      : '';

    output.innerHTML = `
      <div class="dict-result dict-result--${state}" role="status">
        <div class="dict-result__header">
          <span class="dict-result__icon" aria-hidden="true">${icon}</span>
          <span class="dict-result__label">${label}</span>
        </div>
        <p class="dict-result__message">${data.message}</p>
        ${matchChip}
      </div>
    `;
  }


  /* ==========================================================================
     5f. UI RENDERER — renderEntropy
     ==========================================================================
     Builds the Password Entropy visual representation with colored badges.
     ========================================================================== */

  /**
   * Renders the entropy grid of cards.
   *
   * @param {HTMLElement} output - The #entropy-output container div.
   * @param {Object}      data   - The 'entropy' object from /analyze.
   *                               { entropy, charset_size, security_level }
   */
  function renderEntropy(output, data) {
    const levelClassMap = {
      'Very Weak'   : 'entropy-badge--very-weak',
      'Weak'        : 'entropy-badge--weak',
      'Medium'      : 'entropy-badge--medium',
      'Strong'      : 'entropy-badge--strong',
      'Very Strong' : 'entropy-badge--very-strong'
    };
    const badgeClass = levelClassMap[data.security_level] || 'entropy-badge--very-weak';

    output.innerHTML = `
      <div class="entropy-container">
        <div class="entropy-metric-card">
          <span class="entropy-metric-card__label">Entropy</span>
          <span class="entropy-metric-card__value">${data.entropy} bits</span>
        </div>
        <div class="entropy-metric-card">
          <span class="entropy-metric-card__label">Character Set</span>
          <span class="entropy-metric-card__value entropy-metric-card__value--mono">${data.charset_size} characters</span>
        </div>
        <div class="entropy-metric-card">
          <span class="entropy-metric-card__label">Security Level</span>
          <span class="entropy-badge ${badgeClass}">${data.security_level}</span>
        </div>
      </div>
    `;
  }


  /* ==========================================================================
     5g. UI RENDERER — renderCrackTime
     ==========================================================================
     Builds the Estimated Brute Force Crack Time card representation.
     ========================================================================== */

  /**
   * Renders the estimated brute force crack time card.
   *
   * @param {HTMLElement} output - The #crack-time-output container div.
   * @param {Object}      data   - The 'crack_time' object from /analyze.
   *                               { entropy, estimated_crack_time }
   */
  function renderCrackTime(output, data) {
    const isSafe = data.estimated_crack_time.includes('Million') || 
                   data.estimated_crack_time.includes('Billion') || 
                   data.estimated_crack_time.includes('Trillion') ||
                   (data.estimated_crack_time.includes('Years') && !data.estimated_crack_time.includes('1 Year'));

    const safeClass = isSafe ? 'crack-time-card--safe' : '';

    output.innerHTML = `
      <div class="crack-time-card ${safeClass}">
        <div class="crack-time-card__header">
          <span class="crack-time-card__icon" aria-hidden="true">⏳</span>
          <span class="crack-time-card__label">Estimated Time</span>
        </div>
        <span class="crack-time-card__value">${data.estimated_crack_time}</span>
        <p class="crack-time-card__explanation">
          This estimate assumes approximately one billion password guesses per second.
        </p>
      </div>
    `;
  }


  /* ==========================================================================
     6. HELPERS
     ========================================================================== */

  /**
   * clearUI — Resets the results area and error message before a new request.
   *
   * @param {HTMLElement} area        - The results area wrapper.
   * @param {HTMLElement} policyEl    - Policy grid output div.
   * @param {HTMLElement} dictEl      - Dictionary check output div.
   * @param {HTMLElement} entropyEl   - Entropy check output div.
   * @param {HTMLElement} crackTimeEl - Crack time check output div.
   * @param {HTMLElement} suggestEl   - Suggestions list.
   * @param {HTMLElement} errEl       - Error message paragraph.
   */
  function clearUI(area, policyEl, dictEl, entropyEl, crackTimeEl, suggestEl, errEl) {
    // Hide results area and clear all injected HTML
    area.setAttribute('hidden', '');
    policyEl.innerHTML  = '';
    dictEl.innerHTML    = '';
    entropyEl.innerHTML = '';
    crackTimeEl.innerHTML = '';
    suggestEl.innerHTML = '';

    // Hide and clear error
    errEl.setAttribute('hidden', '');
    errEl.textContent = '';
  }

  /**
   * showError — Reveals the error message panel with the given text.
   *
   * @param {HTMLElement} errEl   - The error <p> element.
   * @param {string}      message - Error description.
   */
  function showError(errEl, message) {
    errEl.textContent = message;
    errEl.removeAttribute('hidden');
  }

  /**
   * setLoadingState — Disables/enables the submit button and changes its label.
   *
   * @param {HTMLButtonElement} btn     - The submit button.
   * @param {boolean}           loading - True while the request is in-flight.
   */
  function setLoadingState(btn, loading) {
    btn.disabled = loading;
    btn.innerHTML = loading
      ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
              stroke-linejoin="round" width="16" height="16" aria-hidden="true"
              style="animation:spin 0.8s linear infinite">
           <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
         </svg>
         Analyzing…`
      : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
              stroke-linejoin="round" width="16" height="16" aria-hidden="true">
           <circle cx="11" cy="11" r="8"/>
           <path d="m21 21-4.35-4.35"/>
         </svg>
         Analyze Password`;
  }

});


/* ============================================================
   GLOBAL KEYFRAMES (used by the loading spinner in the button)
   ============================================================ */

const _spinStyle = document.createElement('style');
_spinStyle.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`;
document.head.appendChild(_spinStyle);
