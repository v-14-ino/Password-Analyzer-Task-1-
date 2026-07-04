"""
app.py — Flask Application Entry Point
---------------------------------------
Responsibility:
    - Initializes and configures the Flask web application.
    - Registers all API routes.
    - Serves the frontend static files (index.html).
    - Acts as the main gateway between the frontend and backend logic.
    - Contains NO business logic — all analysis is delegated to analyzer.py.

Module 2 additions:
    - Imports check_password_length() from analyzer.py.
    - POST /analyze calls check_password_length() and returns its result.

Module 3 additions:
    - Imports analyze_character_diversity() from analyzer.py.
    - POST /analyze now returns both length and character diversity results.

Module 4 additions:
    - Imports check_dictionary_password() from analyzer.py.
    - POST /analyze now includes a 'dictionary_check' key:
          { "is_common": bool, "matched_word": str|None, "message": str }

Module 6 additions:
    - Imports calculate_score() from analyzer.py.
    - POST /analyze now includes a 'strength' key in the response:
          { "score": int, "classification": str, "progress": int }

TODO (future steps):
    - Register /api/suggestions route (calls suggestions.py).
    - Add request validation and structured error handlers.
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from analyzer import (
    check_password_length,
    analyze_character_diversity,
    check_dictionary_password,
    check_entropy,
    check_crack_time,
    calculate_score,
    generate_secure_password,
)

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------

# Create the Flask app instance.
# 'static_folder'   — points to the frontend/ directory so Flask can
#                     find and serve CSS, JS, and other assets.
# 'static_url_path' — set to "" (empty string) so static files are served
#                     at the URL root (e.g. GET /style.css, GET /script.js).
#                     The Flask default is "/static", which would make the
#                     browser look for /static/style.css — but the HTML
#                     links to /style.css. Setting this to "" fixes the
#                     404s for all static assets.
# 'template_folder' — points to frontend/ so render_template("index.html")
#                     finds and renders the correct file.
app = Flask(
    __name__,
    static_folder="../frontend",
    static_url_path="",
    template_folder="../frontend"
)

# Enable Cross-Origin Resource Sharing.
# Restrict to local hosting origins to prevent unauthorized cross-origin requests.
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]}})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """
    Homepage Route — GET /
    ----------------------
    Serves the main frontend page (index.html).
    """
    return render_template("index.html")


@app.route("/api/health")
def health_check():
    """
    Health Check Route — GET /api/health
    --------------------------------------
    Confirms the server is running. Useful for debugging and CI checks.
    """
    return jsonify({"status": "ok", "message": "Server is running."})


# ---------------------------------------------------------------------------
# MODULE 1: Password Submission Endpoint
# ---------------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyze Route — POST /analyze
    ------------------------------
    Module 6: Receives a password and returns the length check,
    character diversity, dictionary attack check, and strength score
    in a single response.

    This route is intentionally thin: it only handles HTTP concerns.
    All analysis logic lives in analyzer.py and its dependencies.

    Request body (JSON):
        { "password": "<string>" }

    Response body (JSON):
        {
            "length_check": {
                "length"            : <int>,
                "minimum_required"  : <int>,
                "recommended_length": <int>,
                "passed"            : <bool>,
                "message"           : <str>
            },
            "character_diversity": {
                "uppercase"         : <bool>,
                "lowercase"         : <bool>,
                "numbers"           : <bool>,
                "special_characters": <bool>
            },
            "dictionary_check": {
                "is_common"   : <bool>,
                "matched_word": <str|null>,
                "message"     : <str>
            },
            "strength": {
                "score"          : <int>,
                "classification" : <str>,
                "progress"       : <int>
            }
        }

    HTTP status codes:
        200 — Analysis completed successfully.
        400 — Request body is missing or 'password' key is absent.
    """
    # ── Parse the incoming JSON body ─────────────────────────────────────────────
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    password = data.get("password")
    if password is None:
        return jsonify({"error": "Missing required field: 'password'."}), 400

    # ── Debug print (Secure metadata logging only, no raw passwords) ─────────────────
    masked_pw = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)
    print(f"\n[DEBUG] Password received : '{masked_pw}' (masked)")
    print(f"[DEBUG] Length            : {len(password)} characters")

    # ── Delegate to analyzer.py ────────────────────────────────────────────────────────
    length_result     = check_password_length(password)
    diversity_result  = analyze_character_diversity(password)
    dict_result       = check_dictionary_password(password)
    entropy_result    = check_entropy(password)
    crack_time_result = check_crack_time(password)
    score_result      = calculate_score(password)

    print(f"[DEBUG] Length check      : {'PASSED' if length_result['passed'] else 'FAILED'}")
    print(f"[DEBUG] Uppercase         : {diversity_result['uppercase']}")
    print(f"[DEBUG] Lowercase         : {diversity_result['lowercase']}")
    print(f"[DEBUG] Numbers           : {diversity_result['numbers']}")
    print(f"[DEBUG] Special chars     : {diversity_result['special_characters']}")
    print(f"[DEBUG] Is common         : {dict_result['is_common']}  matched='{dict_result['matched_word']}'")
    print(f"[DEBUG] Entropy           : {entropy_result['entropy']} bits ({entropy_result['security_level']})")
    print(f"[DEBUG] Crack Time Est.   : {crack_time_result['estimated_crack_time']}")
    print(f"[DEBUG] Score             : {score_result['score']} / 100")
    print(f"[DEBUG] Classification    : {score_result['classification']}\n")

    # ── Return combined structured result ───────────────────────────────────────────
    return jsonify({
        "length_check"       : length_result,
        "character_diversity": diversity_result,
        "dictionary_check"   : dict_result,
        "entropy"            : entropy_result,
        "crack_time"         : crack_time_result,
        "strength"           : score_result,
    }), 200


@app.route("/generate", methods=["GET"])
def generate():
    """
    Generate Route — GET /generate
    ------------------------------
    Generates a secure password of a default length (16 characters)
    and returns it as JSON.
    """
    length = request.args.get("length", default=16, type=int)
    if length < 4 or length > 128:
        return jsonify({"error": "Password length must be between 4 and 128 characters."}), 400

    password = generate_secure_password(length)
    return jsonify({"password": password})


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Run in debug mode during development for auto-reloading and error pages.
    # Set debug=False and configure a production WSGI server before deployment.
    app.run(debug=True, port=5000)
