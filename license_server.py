"""
Mediawy Group Share - License Server
=====================================
شغّله على أي VPS أو Render أو Railway
"""

from flask import Flask, request, jsonify
import json, os, hashlib, hmac, secrets, datetime

app = Flask(__name__)

# ── Config ─────────────────────────────────────────────────
DB_FILE     = "licenses.json"
SERVER_SECRET = os.environ.get("SERVER_SECRET", "CHANGE_THIS_SECRET_IN_PRODUCTION")

# ── DB (JSON file - simple & portable) ─────────────────────
def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE) as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

# ── Helpers ─────────────────────────────────────────────────
def sign(data: str) -> str:
    return hmac.new(SERVER_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()

def generate_key() -> str:
    raw = secrets.token_hex(10).upper()
    return f"MWY-{raw[:5]}-{raw[5:10]}-{raw[10:15]}-{raw[15:20]}"

# ── Routes ──────────────────────────────────────────────────

@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    key  = data.get("key", "").strip().upper()
    hwid = data.get("hwid", "").strip().upper()

    if not key or not hwid:
        return jsonify({"ok": False, "msg": "بيانات ناقصة"}), 400

    db = load_db()

    if key not in db:
        return jsonify({"ok": False, "msg": "مفتاح غير صالح"}), 403

    lic = db[key]

    # Revoked?
    if lic.get("revoked"):
        return jsonify({"ok": False, "msg": "هذا المفتاح تم إلغاؤه"}), 403

    # Expired?
    if lic.get("expires"):
        exp = datetime.datetime.fromisoformat(lic["expires"])
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return jsonify({"ok": False, "msg": "انتهت صلاحية المفتاح"}), 403

    # Already bound to different machine?
    if lic.get("hwid") and lic["hwid"] != hwid:
        return jsonify({"ok": False, "msg": "هذا المفتاح مفعّل على جهاز آخر"}), 403

    # First activation - bind to this machine
    if not lic.get("hwid"):
        lic["hwid"]           = hwid
        lic["activated_at"]   = datetime.datetime.now(datetime.timezone.utc).isoformat()
        lic["activations"]    = 1
        db[key] = lic
        save_db(db)

    # Generate a signed session token the client will store locally
    payload  = f"{key}:{hwid}"
    token    = sign(payload)

    return jsonify({
        "ok":    True,
        "msg":   "تم التفعيل بنجاح",
        "token": token,
        "plan":  lic.get("plan", "standard"),
        "owner": lic.get("owner", "")
    })


@app.route("/verify", methods=["POST"])
def verify():
    """Quick online check - called on every app launch."""
    data  = request.json or {}
    key   = data.get("key", "").strip().upper()
    hwid  = data.get("hwid", "").strip().upper()
    token = data.get("token", "").strip()

    if not all([key, hwid, token]):
        return jsonify({"ok": False, "msg": "بيانات ناقصة"}), 400

    db  = load_db()
    lic = db.get(key)

    if not lic:
        return jsonify({"ok": False, "msg": "مفتاح غير موجود"}), 403

    if lic.get("revoked"):
        return jsonify({"ok": False, "msg": "المفتاح ملغي"}), 403

    if lic.get("hwid") != hwid:
        return jsonify({"ok": False, "msg": "جهاز غير مطابق"}), 403

    expected = sign(f"{key}:{hwid}")
    if not hmac.compare_digest(token, expected):
        return jsonify({"ok": False, "msg": "توقيع غير صالح"}), 403

    return jsonify({"ok": True, "msg": "مرخّص"})


# ── Admin Routes (protected by ADMIN_KEY header) ────────────

def admin_guard():
    admin_key = os.environ.get("ADMIN_KEY", "admin123")
    return request.headers.get("X-Admin-Key") == admin_key

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    if not admin_guard():
        return jsonify({"ok": False, "msg": "غير مصرح"}), 401

    data  = request.json or {}
    count = int(data.get("count", 1))
    plan  = data.get("plan", "standard")
    owner = data.get("owner", "")
    days  = data.get("days")  # None = لا يوجد تاريخ انتهاء

    db   = load_db()
    keys = []

    for _ in range(count):
        key = generate_key()
        entry = {
            "plan":       plan,
            "owner":      owner,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "hwid":       None,
            "revoked":    False,
        }
        if days:
            entry["expires"] = (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=int(days))
            ).isoformat()
        db[key]  = entry
        keys.append(key)

    save_db(db)
    return jsonify({"ok": True, "keys": keys})


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not admin_guard():
        return jsonify({"ok": False, "msg": "غير مصرح"}), 401

    key = (request.json or {}).get("key", "").strip().upper()
    db  = load_db()

    if key not in db:
        return jsonify({"ok": False, "msg": "مفتاح غير موجود"}), 404

    db[key]["revoked"] = True
    save_db(db)
    return jsonify({"ok": True, "msg": f"تم إلغاء {key}"})


@app.route("/admin/list", methods=["GET"])
def admin_list():
    if not admin_guard():
        return jsonify({"ok": False, "msg": "غير مصرح"}), 401

    db = load_db()
    return jsonify({"ok": True, "total": len(db), "licenses": db})


@app.route("/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    """Allow user to switch machine (support use case)."""
    if not admin_guard():
        return jsonify({"ok": False, "msg": "غير مصرح"}), 401

    key = (request.json or {}).get("key", "").strip().upper()
    db  = load_db()

    if key not in db:
        return jsonify({"ok": False, "msg": "مفتاح غير موجود"}), 404

    db[key]["hwid"]         = None
    db[key]["activated_at"] = None
    save_db(db)
    return jsonify({"ok": True, "msg": "تم إعادة تعيين الجهاز"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 License Server running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
