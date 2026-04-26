import io
import os

from PIL import Image
from flask import Response
import time
from flask import Flask, render_template, request, session, redirect, url_for, jsonify,flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets, socket
from threading import Thread
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_FILE = "database.db"
# ---------------- LOGIN PAGE ----------------
@app.route("/")
def home():
    return render_template("login.html")
# ---------------- REGISTER ACCOUNT ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        role = request.form.get("role")
        username = request.form.get("username")
        password = request.form.get("password")
        name = request.form.get("name")
        grade = None
        section = None

        # For students
        if role == "user":
            username = request.form.get("student_number")
            grade = request.form.get("grade")
            section = request.form.get("section")

        # For professors
        elif role == "professor":
            username = request.form.get("professor_id")

        # For admins
        elif role == "admin":
            username = request.form.get("username")
            name = request.form.get("name")

        # Ensure password exists
        if not password or not username or not name:
            return jsonify({"success": False, "error": "Please fill all required fields!"})

        hashed_password = generate_password_hash(password)

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Add created date

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                return jsonify({"success": False, "error": "Username/ID already exists!"})

            cur.execute("""
                INSERT INTO users (username, name, password, role, status, grade, section, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, name, hashed_password, role, "pending", grade, section, created_at))
            conn.commit()

        return jsonify({"success": True})

    # GET request
    return render_template("register.html")


@app.route("/admin/users")
def admin_users():
    if "username" not in session or session["role"] != "admin":
        return "Unauthorized", 403

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, status, created_by FROM users WHERE status = ?", ("pending",))
        pending_users = cur.fetchall()

    return render_template("admin_users.html", pending_users=pending_users)
def monitor_devices(username):
    """Monitors USB devices and prints connection/disconnection events."""
    print(f"\n🕵️ Monitoring USB/peripheral devices for user: {username}...")
# ---------------- api LOGIN ACCOUNT ----------------
@app.route("/api/logged_in_user")
def get_logged_in_user():
    pc_tag = request.form.get("pc_tag") or request.args.get("pc_tag") or socket.gethostname()
    if not pc_tag:
        return jsonify({"error": "Missing pc_tag"}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT student_name, student_id FROM active_sessions WHERE pc_tag=?", (pc_tag,))
        row = cur.fetchone()

        if row:
            student_name = row[0]
            student_id = row[1]

            # Get device_name from devices table
            cur.execute("SELECT tag,location FROM devices WHERE hostname = ?", (pc_tag,))
            device_row = cur.fetchone()
            if device_row:
                tag, location = device_row
            else:
                tag, location = None,None


            return jsonify({
                "username": student_name,
                "user_id": student_id,
                "device_name": tag,
                "location": location
            })

        # Return empty JSON when no logged-in user
        return jsonify({
            "username": None,
            "user_id": None,
            "device_name": None,
            "location": None

        })
# ---------------- LOGIN ACCOUNT ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    pc_tag = (
        request.form.get("pc_tag")
        or request.args.get("pc_tag")
        or session.get("pc_tag")
        or ""
    ).strip()

    if not pc_tag:
        pc_tag = socket.gethostname()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()

            cur.execute("""
                SELECT username, password, role, status, name
                FROM users
                WHERE username = ?
            """, (username,))
            row = cur.fetchone()

            if not row:
                flash("Invalid username or password!", "error")
                return redirect(url_for("login", pc_tag=pc_tag))

            username_db, password_db, role, status, student_name = row

            if status == "pending":
                flash("Your account is pending. Please wait for admin approval.", "error")
                return redirect(url_for("login", pc_tag=pc_tag))

            if not check_password_hash(password_db, password):
                flash("Invalid username or password!", "error")
                return redirect(url_for("login", pc_tag=pc_tag))

            # Save session
            session["username"] = username_db
            session["role"] = role
            session["pc_tag"] = pc_tag
            session["login_time"] = int(time.time())
            session.modified = True

            if role == "admin":
                return redirect(url_for("admin_dashboard"))

            if role in ["user", "professor"]:
                cur.execute("""
                    DELETE FROM active_sessions
                    WHERE student_id = ?
                       OR pc_tag = ?
                """, (username_db, pc_tag))

                cur.execute("""
                    INSERT INTO active_sessions
                    (pc_tag, student_id, login_time, student_name)
                    VALUES (?, ?, ?, ?)
                """, (pc_tag, username_db, login_time, student_name))

                conn.commit()

                return redirect(url_for("student_dashboard"))

            flash("Unknown account role.", "error")
            return redirect(url_for("login", pc_tag=pc_tag))

    return render_template("login.html", pc_tag=pc_tag)

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
def admin_dashboard():
    edit_mode = request.args.get("edit", "0") == "1"
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM labs ORDER BY id ASC")
        labs = cur.fetchall()
    return render_template("admin_dashboard.html", labs=labs, edit_mode=edit_mode)
@app.route("/register_device/<token>", methods=["GET", "POST"])
def register_device(token):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM labs")
        comlabs = cur.fetchall()
        cur.execute("SELECT id, used FROM device_tokens WHERE token = ?", (token,))
        row = cur.fetchone()

        if not row:
            return "Invalid or expired link.", 400
        if row[1] == 1:
            return "This link has already been used.", 400

        if request.method == "POST":
            tag = request.form["tag"]
            location = request.form["location"]
            hostname = socket.gethostname()
            ip_addr = request.remote_addr
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            comlab_id = int(location)

            # --- Check if device already exists in another comlab ---
            cur.execute("""
                        SELECT comlab_id
                        FROM devices
                        WHERE tag = ?
                           OR hostname = ?
                        """, (tag, hostname))
            existing = cur.fetchone()

            if existing:
                return f"⚠️ Device already registered in ComLab {existing[0]}. Cannot register in another ComLab.", 400

            # --- Insert device since it's not registered anywhere else ---
            conn.execute("""
                         INSERT INTO devices (tag, location, hostname, ip_address, created_at, comlab_id)
                         VALUES (?, ?, ?, ?, ?, ?)
                         """, (tag, location, hostname, ip_addr, created_at, comlab_id))

            conn.execute("UPDATE device_tokens SET used = 1 WHERE id = ?", (row[0],))
            conn.commit()

            return render_template("success.html", tag=tag, hostname=hostname, ip=ip_addr)

    return render_template("register_device.html", comlabs=comlabs)

@app.route("/generate_link", methods=["GET"])
def generate_link():
    token = secrets.token_urlsafe(16)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO device_tokens (token, created_at) VALUES (?, ?)",
            (token, created_at)
        )
        conn.commit()

        # ---- GET LATEST COMLABS ----
        comlabs = conn.execute("SELECT id, name FROM labs").fetchall()

    link = url_for("register_device", token=token, _external=True)
    return render_template("link_generated.html", link=link, comlabs=comlabs)
@app.route("/logout")
def logout():
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))
from datetime import datetime
from flask import session, flash, redirect, url_for
import sqlite3

@app.route("/user/logout")
def user_logout():
    logged_in_student = session.get("username")

    if logged_in_student:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("""
                DELETE FROM active_sessions
                WHERE student_id = ?
            """, (logged_in_student,))
            conn.commit()

    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))
@app.route("/add_lab", methods=["POST"])
def add_lab():
    data = request.get_json()
    lab_name = data.get("lab_name", "").strip()

    if lab_name == "":
        return jsonify({"message": "Lab name cannot be empty."}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        # Check if existing
        cur.execute("SELECT name FROM labs WHERE LOWER(name) = LOWER(?)", (lab_name,))
        exists = cur.fetchone()
        if exists:
            return jsonify({"message": "Lab already exists!"}), 400
        cur.execute("INSERT INTO labs (name) VALUES (?)", (lab_name,))
        conn.commit()
    return jsonify({"message": f"{lab_name} added successfully!"})
@app.route("/rename_lab", methods=["POST"])
def rename_lab():
    data = request.get_json()
    lab_id = data.get("id")
    new_name = data.get("new_name").strip()

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE labs SET name = ? WHERE id = ?", (new_name, lab_id))
        conn.commit()

    return jsonify({"message": "Lab renamed successfully!"})
@app.route("/remove_lab", methods=["POST"])
def remove_lab():
    data = request.get_json()
    lab_id = data.get("id")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM labs WHERE id = ?", (lab_id,))
        cur.execute("DELETE FROM devices WHERE comlab_id = ?", (lab_id,))

        conn.commit()

    return jsonify({"message": "Lab removed successfully!"})

@app.route("/comlab/<int:comlab_id>")
def comlab_view(comlab_id):
    logged_in_student = session.get("username")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM labs WHERE id = ?", (comlab_id,))
        lab_row = cur.fetchone()
        lab_name = lab_row["name"] if lab_row else f"Computer Lab #{comlab_id}"

        cur.execute("""
            SELECT id, tag, hostname, location, comlab_id
            FROM devices
            WHERE location = ? OR comlab_id = ?
            ORDER BY tag ASC
        """, (str(comlab_id), comlab_id))

        devices = []

        for row in cur.fetchall():
            device = dict(row)

            # Check using PC tag OR hostname para hindi mawala ang In Use display
            cur.execute("""
                SELECT student_name, student_id, login_time, pc_tag
                FROM active_sessions
                WHERE pc_tag = ?
                   OR pc_tag = ?
                ORDER BY login_time DESC
                LIMIT 1
            """, (
                device["tag"],
                device["hostname"] if device.get("hostname") else ""
            ))

            active = cur.fetchone()

            if active:
                device["student_name"] = active["student_name"]
                device["student_id"] = active["student_id"]
                device["login_time"] = active["login_time"]
                device["active_pc_tag"] = active["pc_tag"]
            else:
                device["student_name"] = None
                device["student_id"] = None
                device["login_time"] = None
                device["active_pc_tag"] = None

            devices.append(device)

    return render_template(
        "comlab_view.html",
        comlab_id=comlab_id,
        lab_name=lab_name,
        devices=devices,
        logged_in_student=logged_in_student
    )
@app.route("/account-management")
def account_management():

    account_type = request.args.get("type", "user")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        if account_type == "user":
            cur.execute("""
                        SELECT id, username, name, password, grade, section, role, created_at
                        FROM users
                        WHERE (role = 'user' OR role = 'professor') AND status = 'active'
                        ORDER BY id DESC
                        """)
        else:  # admin
            cur.execute("""
                        SELECT id, username, name, password, created_at, role
                        FROM users
                        WHERE role = 'admin'
                          AND status = 'active'
                        ORDER BY id DESC
                        """)
        data = cur.fetchall()
    # Convert Row to dict para mas safe sa Jinja
    data = [dict(row) for row in data]

    return render_template("account_management.html", data=data, account_type=account_type)

@app.route("/delete/<account_type>/<int:user_id>", methods=["POST"])
def delete_account(account_type, user_id):
    if "username" not in session or session["role"] != "admin":
        return jsonify({"status": "Unauthorized"}), 403

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error"}), 500

@app.route("/pending_accounts")
def pending_accounts():

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, name, grade, section, role, created_at FROM users WHERE status='pending' ORDER BY id DESC")
        pending = [dict(row) for row in cur.fetchall()]

    return jsonify(pending)

@app.route("/approve/<int:user_id>", methods=["POST"])
def approve_account(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
        conn.commit()
    return redirect(url_for("account_management"))


@app.route("/reject/<int:user_id>", methods=["POST"])
def reject_account(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    return redirect(url_for("account_management"))

@app.route("/comlab/<int:lab_id>/inventory")
def comlab_inventory(lab_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Fetch devices in this lab
    c.execute("""
        SELECT id, tag
        FROM devices
        WHERE location = ?
        ORDER BY tag ASC
    """, (str(lab_id),))
    devices = [dict(row) for row in c.fetchall()]

    # Fetch peripherals
    c.execute("""
        SELECT id, name, brand, unique_id, serial_number, assigned_pc, status, remarks
        FROM peripherals
        WHERE lab_id = ?
        ORDER BY assigned_pc ASC, name ASC
    """, (str(lab_id),))
    rows = c.fetchall()

    peripherals_by_pc = {}
    for row in rows:
        assigned_pc = row["assigned_pc"]
        peripherals_by_pc.setdefault(assigned_pc, []).append({
            "id": row["id"],
            "name": row["name"],
            "brand": row["brand"],
            "unique_id": row["unique_id"],
            "serial_number": row["serial_number"],
            "status": row["status"],
            "remarks": row["remarks"]
        })

    # Attach peripherals and active user to each PC.
    # IMPORTANT: use each device tag, not the Flask server hostname.
    for d in devices:
        d["peripherals"] = peripherals_by_pc.get(d["tag"], [])

        c.execute("""
            SELECT student_name, student_id
            FROM active_sessions
            WHERE pc_tag = ?
            LIMIT 1
        """, (d["tag"],))
        session_row = c.fetchone()

        if session_row:
            d["student_name"] = session_row["student_name"]
            d["student_id"] = session_row["student_id"]
            d["is_in_use"] = True
        else:
            d["student_name"] = None
            d["student_id"] = None
            d["is_in_use"] = False

    conn.close()

    return render_template(
        "inventory.html",
        devices=devices,
        comlab_id=lab_id,
        lab_name=f"Lab {lab_id}"
    )

@app.route("/api/add_peripheral", methods=["POST"])
def api_add_peripheral():
    data = request.get_json()
    name = data.get("name")
    brand = data.get("brand")
    assigned_pc = data.get("pc_tag")  # from front-end
    lab_id = data.get("lab_id")
    unique_id = data.get("unique_id", "")
    serial_number = data.get("serial_number", "")
    status = "CONNECTED"  # default

    if not name or not brand or not assigned_pc or not lab_id:
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO peripherals (name, brand, assigned_pc, lab_id, unique_id, serial_number, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (name, brand, assigned_pc, lab_id, unique_id, serial_number, status))

    conn.commit()
    peripheral_id = c.lastrowid
    conn.close()

    return jsonify({
        "success": True,
        "peripheral": {
            "id": peripheral_id,
            "name": name,
            "brand": brand,
            "assigned_pc": assigned_pc,
            "unique_id": unique_id,
            "serial_number": serial_number,
            "status": status
        }
    })


@app.route("/api/delete_peripheral", methods=["POST"])
def api_delete_peripheral():
    data = request.get_json()
    pid = data.get("id")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("DELETE FROM peripherals WHERE id = ?", (pid,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route("/comlab/<int:comlab_id>/add_peripheral", methods=["POST"])
def add_peripheral(comlab_id):
    data = request.get_json()
    pc_tag = data.get("pc_tag")
    name = data.get("name")
    brand = data.get("brand")
    unique_id = data.get("unique_id")
    remarks = data.get("remarks")
    serial = data.get("serial_number")
    if not all([pc_tag, name, brand, serial]):
        return jsonify({"success": False, "message": "Missing fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # devices table uses "location", not comlab_id
    cur.execute("SELECT id FROM devices WHERE tag = ? AND location = ?", (pc_tag, str(comlab_id)))
    device = cur.fetchone()
    if not device:
        conn.close()
        return jsonify({"success": False, "message": f"PC '{pc_tag}' not found in this ComLab"}), 404
    cur.execute("""
                SELECT id
                FROM peripherals
                WHERE assigned_pc = ?
                  AND name = ?
                """, (pc_tag, name))
    existing = cur.fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": f"{name} already exists for {pc_tag}"}), 400
    # Insert peripheral
    cur.execute("""
        INSERT INTO peripherals (name, brand,unique_id, serial_number, status, remarks, lab_id, assigned_pc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, brand,unique_id, serial, 'connected','', str(comlab_id), pc_tag))
    conn.commit()
    peripheral_id = cur.lastrowid
    conn.close()

    return jsonify({
        "success": True,
        "peripheral": {
            "id": peripheral_id,
            "name": name,
            "brand": brand,
            "unique_id": unique_id,
            "serial_number": serial,
            "status": 'connected',
            "remarks": ''
        }
    })

@app.route("/api/edit_peripheral", methods=["POST"])
def api_edit_peripheral():
    data = request.get_json()

    pid = data.get("id")
    name = data.get("name")
    brand = data.get("brand")
    serial = data.get("serial_number")
    unique_id = data.get("unique_id")
    remarks = data.get("remarks")
    if not pid or not name or not brand:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            UPDATE peripherals
            SET name=?, brand=?, unique_id=?, serial_number=?, remarks=?
            WHERE id=?
        """, (name, brand,unique_id, serial,remarks, pid))
        conn.commit()
        conn.close()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/delete_peripheral", methods=["POST"])
def delete_peripheral():
    data = request.get_json()
    pid = data.get("id")

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM peripherals WHERE id = ?", (pid,))
            conn.commit()

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Student Dashboard
@app.route("/student_dashboard")
def student_dashboard():
    username = session.get("username")
    login_time = session.get("login_time", int(time.time()))

    if not username:
        return redirect("/login")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT username, name, email, grade, section, contact, profile_pic
            FROM users
            WHERE username = ?
        """, (username,))
        student = cur.fetchone()

        cur.execute("""
            UPDATE student_notifications
            SET is_read = 1
            WHERE student_id = ?
              AND is_read = 0
        """, (username,))
        conn.commit()

        # Kunin kung anong PC ang currently gamit ng student/professor
        cur.execute("""
            SELECT pc_tag
            FROM active_sessions
            WHERE student_id = ?
            ORDER BY datetime(login_time) DESC
            LIMIT 1
        """, (username,))
        active_pc = cur.fetchone()

        current_pc_tag = active_pc["pc_tag"] if active_pc else None

        # Display anomalies/devices for the current PC
        if current_pc_tag:
            cur.execute("""
                SELECT
                    a.location,
                    a.device_name,
                    a.event_type,
                    a.device_type,
                    COALESCE(p.unique_id, a.serial_number) AS unique_id,
                    a.timestamp,
                    a.alert_type,
                    a.deleted
                FROM peripheral_alerts a
                LEFT JOIN peripherals p
                    ON a.serial_number = p.serial_number
                WHERE a.deleted = 0
                  AND (
                        a.user_id = ?
                        OR a.device_name = ?
                      )
                ORDER BY datetime(a.timestamp) DESC
            """, (username, current_pc_tag))
        else:
            cur.execute("""
                SELECT
                    a.location,
                    a.device_name,
                    a.event_type,
                    a.device_type,
                    COALESCE(p.unique_id, a.serial_number) AS unique_id,
                    a.timestamp,
                    a.alert_type,
                    a.deleted
                FROM peripheral_alerts a
                LEFT JOIN peripherals p
                    ON a.serial_number = p.serial_number
                WHERE a.deleted = 0
                  AND a.user_id = ?
                ORDER BY datetime(a.timestamp) DESC
            """, (username,))

        anomalies = cur.fetchall()

        cur.execute("""
            SELECT status
            FROM emergency_logout_requests
            WHERE student_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (username,))
        req = cur.fetchone()

        if req:
            if req["status"] == "approved":
                flash("Your emergency logout request was approved!", "success")
            elif req["status"] == "declined":
                flash("Your emergency logout request was declined.", "error")

    return render_template(
        "student_dashboard.html",
        student=student,
        anomalies=anomalies,
        login_time=login_time
    )
# Upload profile picture
@app.route("/upload_profile", methods=["POST"])
def upload_profile():

    if "profile_pic" not in request.files:
        flash("No file selected.", "error")
        return redirect("/student_dashboard")

    file = request.files["profile_pic"]
    if file.filename == "":
        flash("No selected file.", "error")
        return redirect("/student_dashboard")

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET profile_pic=? WHERE username=?", (filepath, session["username"]))
            conn.commit()

        flash("Profile picture updated!", "success")
    else:
        flash("Invalid file type.", "error")

    return redirect("/student_dashboard")


# Change Password (via modal or icon)
@app.route("/change_password", methods=["POST"])
def change_password():

    current_pw = request.form.get("current_password")
    new_pw = request.form.get("new_password")
    confirm_pw = request.form.get("confirm_password")

    if not current_pw or not new_pw or not confirm_pw:
        flash("Please fill all fields.", "error")
        return redirect("/student_dashboard")

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return redirect("/student_dashboard")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=?", (session["username"],))
        row = cur.fetchone()
        if row and check_password_hash(row[0], current_pw):
            hashed_pw = generate_password_hash(new_pw)
            cur.execute("UPDATE users SET password=? WHERE username=?", (hashed_pw, session["username"]))
            conn.commit()
            flash("Password changed successfully!", "success")
        else:
            flash("Current password incorrect.", "error")

    return redirect("/student_dashboard")


# View/Edit profile (admin verification required)
@app.route("/edit_profile", methods=["POST"])
def edit_profile():
    submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Add created date
    data = request.form
    # Store changes as "pending" in a separate table for admin verification
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO profile_edits_pending 
            (username, full_name, grade, section, email, contact , submitted_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session["username"], data["full_name"], data["grade"], data["section"], data["email"], data["contact"], submitted_at , "pending"))
        conn.commit()

    flash("Profile edit request submitted for admin verification.", "success")
    return redirect("/student_dashboard")

@app.route("/api/profile_edits_pending")
def api_profile_edits_pending():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, full_name, grade, section, email, contact, submitted_at FROM profile_edits_pending WHERE status='pending'")
        rows = cur.fetchall()
        data = [dict(zip(["id","username","full_name","grade","section","email","contact","submitted_at"], row)) for row in rows]
    return jsonify(data)

@app.route("/approve_edit/<int:edit_id>", methods=["POST"])
def approve_edit(edit_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        # Get pending edit
        cur.execute("SELECT username, full_name, grade, section, email, contact FROM profile_edits_pending WHERE id=?", (edit_id,))
        row = cur.fetchone()
        if row:
            username, full_name, grade, section, email, contact = row
            # Update users table
            cur.execute("""UPDATE users SET name=?, grade=?, section=?, email=?, contact=? WHERE username=?""",
                        (full_name, grade, section, email, contact, username))
            # Mark pending edit as approved
            cur.execute("UPDATE profile_edits_pending SET status='approved' WHERE id=?", (edit_id,))
            conn.commit()
    return redirect(url_for("account_management"))

@app.route("/reject_edit/<int:edit_id>", methods=["POST"])
def reject_edit(edit_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE profile_edits_pending SET status='rejected' WHERE id=?", (edit_id,))
        conn.commit()
    return redirect(url_for("account_management"))

@app.route("/api/usb_event", methods=['POST'])
def usb_event():
    from datetime import datetime
    data = request.get_json()
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # INSERT USB EVENT
        cur.execute("""
            INSERT INTO usb_devices 
            (event_type, device_type, vendor, product, unique_id, username, timestamp, pc_tag, user_id, device_name, location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['event_type'], data['device_type'], data['vendor'], data['product'],data['unique_id'], data['username'], timestamp, data['pc_tag'],
            data['user_id'], data['device_name'], data['location']
        ))
        # 1) UPDATE STATUS BASED ON CONNECT / UNPLUG
        new_status = None
        alert_type = None

        if data['event_type'] == "connected":
            cur.execute("""
                            SELECT serial_number FROM peripherals
                            WHERE name = ? AND lab_id = ? AND assigned_pc = ?
                        """, ( data['device_type'], data['location'], data['device_name']))
            device = cur.fetchone()
            if device:
                if device:
                    serial_number = device[0]
                    if serial_number != data['unique_id']:
                        new_status = "replaced"
                        alert_type = "replaced"
                    else:
                        new_status = "connected"
                # Update status
                print("new status",new_status)
                cur.execute("""
                        UPDATE peripherals
                        SET status = ?
                        WHERE name = ? AND lab_id = ? AND assigned_pc = ?
                    """, (new_status, data['device_type'], data['location'], data['device_name']))
                if alert_type:
                    cur.execute("""
                        INSERT INTO peripheral_alerts (serial_number, alert_type, timestamp, device_name, location, event_type, device_type, user_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (data['unique_id'], alert_type, timestamp, data['device_name'], data['location'],
                          data['event_type'], data['device_type'], data['user_id']))
        elif data['event_type'] == "disconnected":
            new_status = "unplugged"

        if new_status:
            cur.execute("""
                UPDATE peripherals
                SET status = ?
                WHERE name = ? AND serial_number = ? AND assigned_pc = ?
            """, (new_status, data['device_type'], data['unique_id'], data['device_name']))

        cur.execute("""
                INSERT INTO peripheral_logs (unique_id, event_type, device_type, timestamp, device_name)
                VALUES (?, ?, ?, ?, ?)
            """, (data['unique_id'], data['event_type'], data['device_type'], timestamp, data['device_name']))

        cur.execute("""
                SELECT event_type
                FROM peripheral_logs
                WHERE unique_id = ?
                  AND datetime(timestamp) >= datetime('now', '-10 minutes')
                ORDER BY datetime(timestamp) ASC
            """, (data['unique_id'],))

        events = [row[0] for row in cur.fetchall()]
        cycle_count = 0

        for i in range(len(events) - 1):
            if events[i] == "connected" and events[i + 1] == "disconnected":
                cycle_count += 1

        if cycle_count >= 3:
            cur.execute("""
                    UPDATE peripherals
                    SET status = 'faulty'
                    WHERE serial_number = ?
                """, (data['unique_id'],))
            alert_type = "faulty"
            if alert_type:
                cur.execute("""
                    INSERT INTO peripheral_alerts (serial_number, alert_type, timestamp, device_name, location, event_type, device_type, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (data['unique_id'], alert_type, timestamp, data['device_name'], data['location'], data['event_type'], data['device_type'], data['user_id']))

        #   MISSING CHECK (last disconnected older than 10min)
        cur.execute("""
                SELECT timestamp FROM peripheral_logs
                WHERE unique_id = ?
                  AND event_type = 'disconnected'
                ORDER BY timestamp DESC LIMIT 1
            """, (data['unique_id'],))

        last_unplug = cur.fetchone()

        if last_unplug:
            ts = last_unplug[0]

            try:
                last_unplug_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except:
                last_unplug_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")

            now = datetime.now()

            if (now - last_unplug_time).total_seconds() >= 600:  # 10 minutes
                cur.execute("""
                        UPDATE peripherals
                        SET status = 'missing'
                        WHERE serial_number = ?
                    """, (data['unique_id'],))
                alert_type = "missing"
                if alert_type:
                    cur.execute("""
                        INSERT INTO peripheral_alerts (serial_number, alert_type, timestamp, device_name, location, event_type, device_type, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (data['unique_id'], alert_type, timestamp, data['device_name'], data['location'], data['event_type'], data['device_type'], data['user_id']))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "alert": alert_type
        }), 200

    except sqlite3.Error as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/comlab/<int:comlab_id>/inventory/display_usb_devices")
def display_usb_devices(comlab_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM usb_devices WHERE location = ? ORDER BY timestamp DESC", (comlab_id,))
        devices = cur.fetchall()
        conn.close()

        devices_list = []
        column_names = [description[0] for description in cur.description]
        for device in devices:
            device_dict = dict(zip(column_names, device))
            devices_list.append(device_dict)

        return render_template("usb_devices.html", devices=devices_list, comlab_id=comlab_id)

    except sqlite3.Error as e:
        return f"<h1>Database Error:</h1><p>{str(e)}</p>", 500

@app.route("/comlab/<int:comlab_id>/inventory/view_alerts")
def view_alerts(comlab_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""SELECT B.unique_id,A.* FROM peripheral_alerts A INNER JOIN peripherals B 
                    ON A.serial_number = B.serial_number 
                    WHERE A.location = ? AND A.deleted = 0 ORDER BY timestamp DESC""", (comlab_id,))
        devices = cur.fetchall()
        conn.close()

        devices_list = []
        column_names = [description[0] for description in cur.description]
        for device in devices:
            device_dict = dict(zip(column_names, device))
            devices_list.append(device_dict)

        return render_template("view_alerts.html", devices=devices_list, comlab_id=comlab_id)

    except sqlite3.Error as e:
        return f"<h1>Database Error:</h1><p>{str(e)}</p>", 500

@app.route("/alerts/stream")
def alerts_stream():
    def event_stream():
        last_id = 0
        while True:
            with sqlite3.connect(DB_FILE) as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, serial_number, alert_type, location, timestamp
                    FROM peripheral_alerts
                    WHERE id > ? AND deleted = 0
                    ORDER BY id ASC
                """, (last_id,))
                rows = cur.fetchall()
                for row in rows:
                    last_id = row[0]
                    yield f"data: {row[3]}|{row[1]}|{row[2]}\n\n"  # location|serial_number|alert_type
            time.sleep(2)  # check every 2 seconds
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/comlab/<int:comlab_id>/inventory/summary")
def summary(comlab_id):
    import sqlite3
    from flask import request, render_template

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # --- GET FILTERS ---
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    peripheral_type = request.args.get("peripheral_type")
    pc_no = request.args.get("pc_no")
    alert_type_filter = request.args.get("alert_type")

    # --- BASE QUERIES ---
    pc_query = "SELECT COUNT(*) FROM devices WHERE location=?"
    anomaly_query = "SELECT COUNT(*) FROM usb_devices WHERE location=?"
    alert_query = "SELECT COUNT(*) FROM peripheral_alerts WHERE location=?"

    pc_params = [comlab_id]
    anomaly_params = [comlab_id]
    alert_params = [comlab_id]

    # --- APPLY FILTERS ---
    if start_date and end_date:
        anomaly_query += " AND date(timestamp) BETWEEN ? AND ?"
        anomaly_params.extend([start_date, end_date])
        alert_query += " AND date(timestamp) BETWEEN ? AND ?"
        alert_params.extend([start_date, end_date])

    if pc_no:
        pc_query += " AND tag=?"
        pc_params.append(pc_no)
        anomaly_query += " AND device_name=?"
        anomaly_params.append(pc_no)
        alert_query += " AND device_name=?"
        alert_params.append(pc_no)

    if peripheral_type:
        anomaly_query += " AND device_type=?"
        anomaly_params.append(peripheral_type)
        alert_query += " AND device_type=?"
        alert_params.append(peripheral_type)

    if alert_type_filter:
        alert_query += " AND alert_type=?"
        alert_params.append(alert_type_filter.lower())

    # --- EXECUTE QUERIES ---
    cur.execute(pc_query, pc_params)
    pc_count = cur.fetchone()[0]

    cur.execute(anomaly_query, anomaly_params)
    anomaly_count = cur.fetchone()[0]

    # --- PERIPHERALS BREAKDOWN ---
    all_types = ['Mouse','Keyboard','Monitor','Speaker','Webcam','FlashDrive','Hard Disk','Scanner','Printer']
    peripheral_counts = []

    for t in all_types:
        q = "SELECT COUNT(*) FROM peripherals WHERE lab_id=? AND name=?"
        params = [comlab_id, t]
        if pc_no:
            q += " AND assigned_pc=?"
            params.append(pc_no)
        # Apply peripheral_type filter
        if peripheral_type and peripheral_type.lower() != t.lower():
            peripheral_counts.append(0)
            continue
        cur.execute(q, params)
        peripheral_counts.append(cur.fetchone()[0])

    # --- ALERTS BREAKDOWN ---
    alert_types = ['missing', 'faulty', 'replaced']
    alert_counts = {}
    for at in alert_types:
        # Only count this type if alert_type_filter not set or matches
        if alert_type_filter and alert_type_filter.lower() != at:
            alert_counts[at] = 0
            continue

        q = "SELECT COUNT(*) FROM peripheral_alerts WHERE location=? AND alert_type=?"
        params = [comlab_id, at]
        if start_date and end_date:
            q += " AND date(timestamp) BETWEEN ? AND ?"
            params.extend([start_date, end_date])
        if pc_no:
            q += " AND device_name=?"
            params.append(pc_no)
        if peripheral_type:
            q += " AND device_type=?"
            params.append(peripheral_type)
        cur.execute(q, params)
        alert_counts[at] = cur.fetchone()[0]

    alert_count = sum(alert_counts.values())
    conn.close()

    # --- RENDER TEMPLATE ---
    return render_template(
        "view_summary.html",
        comlab_id=comlab_id,
        pc_count=pc_count,
        peripheral_counts=peripheral_counts,
        anomaly_count=anomaly_count,
        alert_count=alert_count,
        alert_counts=alert_counts,
        types=all_types,
        request=request
    )


@app.route("/pending_accounts/count")
def pending_accounts_count():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE status='pending'")
        count = cur.fetchone()[0]
    return jsonify({"count": count})

@app.route("/api/profile_edits_pending/count")
def profile_edits_pending_count():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM profile_edits_pending WHERE status='pending'")
        count = cur.fetchone()[0]
    return jsonify({"count": count})

@app.route("/api/delete_device", methods=["POST"])
def delete_device():
    data = request.get_json()
    device_id = data.get("id")

    if not device_id:
        return jsonify({"success": False, "message": "Device ID not provided"}), 400

    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        cur.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/delete_alert/<int:alert_id>", methods=["DELETE"])
def delete_alert(alert_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("UPDATE peripheral_alerts SET deleted = 1 WHERE id=?", (alert_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        print("Error deleting alert:", e)
        return jsonify({"success": False, "error": str(e)}), 500
@app.route("/deleted_alerts/<comlab_id>")
def deleted_alerts(comlab_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
           SELECT a.id,a.serial_number, a.alert_type, a.device_name, a.device_type, a.user_id, a.timestamp, b.unique_id
           FROM peripheral_alerts a
           inner join peripherals b
           on a.serial_number = b.serial_number
           WHERE a.deleted = 1 AND a.location = ?
           ORDER BY timestamp DESC
       """, (comlab_id,))
    rows = cur.fetchall()

    return jsonify([
        {
            "id": r[0],  # <-- primary key
            "serial_number": r[1],
            "alert_type": r[2],
            "device_name": r[3],
            "device_type": r[4],
            "user_id": r[5],
            "timestamp": r[6],
            "unique_id": r[7]
        }
        for r in rows
    ])
@app.route("/restore_alert/<alert_id>", methods=["POST"])
def restore_alert(alert_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute("UPDATE peripheral_alerts SET deleted=0 WHERE id=?", (alert_id,))
        conn.commit()
        success = cur.rowcount > 0
    except Exception as e:
        print(e)
        success = False
    finally:
        conn.close()
    return jsonify({"success": success})

@app.route("/request_emergency_logout", methods=["POST"])
def request_emergency_logout():
    if "username" not in session:
        return jsonify({"message": "Not logged in"}), 401

    username = session["username"]

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO emergency_logout_requests (student_id, timestamp)
            VALUES (?, datetime('now'))
        """, (username,))
        conn.commit()

    return jsonify({"message": "Emergency logout request sent to admin!"})
@app.route("/admin/get_emergency_requests")
def get_emergency_requests():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM emergency_logout_requests WHERE status='pending'")
        rows = cur.fetchall()

    return jsonify([dict(r) for r in rows])
@app.route("/admin/decline_logout/<int:req_id>")
def decline_logout(req_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        cur.execute("SELECT student_id FROM emergency_logout_requests WHERE id=?", (req_id,))
        row = cur.fetchone()

        if not row:
            return "Request not found"

        student_id = row[0]

        # update status
        cur.execute("UPDATE emergency_logout_requests SET status='declined' WHERE id=?", (req_id,))
        conn.commit()

        # insert notification
        cur.execute("""
            INSERT INTO student_notifications (student_id, message, created_at)
            VALUES (?, ?, datetime('now'))
        """, (student_id, "Your emergency logout request has been DECLINED."))
        conn.commit()

    return "Request Declined"


@app.route("/admin/approve_logout/<int:req_id>")
def approve_logout(req_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        # Get student ID from request
        cur.execute("SELECT student_id FROM emergency_logout_requests WHERE id=?", (req_id,))
        row = cur.fetchone()

        if not row:
            return "Request not found"

        student_id = row[0]

        # Update request status
        cur.execute("UPDATE emergency_logout_requests SET status='approved' WHERE id=?", (req_id,))
        conn.commit()

        # Force logout the student
        cur.execute("UPDATE users SET force_logout = 1 WHERE username = ?", (student_id,))
        conn.commit()

        # Notify the student
        cur.execute("""
            INSERT INTO student_notifications (student_id, message, created_at)
            VALUES (?, ?, datetime('now'))
        """, (student_id, "Your emergency logout request has been approved."))
        conn.commit()
    return "Logout Approved"

@app.route("/comlab/<int:comlab_id>/inventory/peripheral")
def peripheral_summary(comlab_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT 
                assigned_pc,name,brand,serial_number,unique_id,status,remarks
            FROM peripherals
            WHERE lab_id = ?
            ORDER BY assigned_pc ASC
        """, (comlab_id,))

        peripherals = cur.fetchall()
        conn.close()

        return render_template(
            "peripheral_summary.html",
            peripherals=peripherals,
            comlab_id=comlab_id
        )

    except Exception as e:
        return f"DB Error: {e}", 500
@app.route("/update_peripheral_remarks", methods=["POST"])
def update_peripheral_remarks():

    data = request.json
    unique_id = data["unique_id"]
    new_remarks = data["remarks"]
    user = session.get("username")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        # get old remarks
        cur.execute("SELECT remarks FROM peripherals WHERE unique_id=?", (unique_id,))
        old = cur.fetchone()
        old_remarks = old[0] if old else ""

        # update main table
        cur.execute(
            "UPDATE peripherals SET remarks=? WHERE unique_id=?",
            (new_remarks, unique_id)
        )

        # insert history
        cur.execute("""
            INSERT INTO peripheral_remarks_history
            (unique_id, old_remarks, new_remarks, updated_by)
            VALUES (?,?,?,?)
        """, (unique_id, old_remarks, new_remarks, user))

        conn.commit()

    return jsonify({"success": True})
@app.route("/peripheral/<unique_id>/remarks_history")
def remarks_history(unique_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT old_remarks, new_remarks, updated_by, updated_at
            FROM peripheral_remarks_history
            WHERE unique_id=?
            ORDER BY updated_at DESC
        """, (unique_id,))
        rows = cur.fetchall()

    return jsonify([
        {
            "old": r[0],
            "new": r[1],
            "by": r[2],
            "at": r[3]
        } for r in rows
    ])

@app.route('/api/check_logout')
def check_logout():
    try:
        if "username" in session:
            username = session["username"]
            with sqlite3.connect(DB_FILE) as conn:
                cur = conn.cursor()
                cur.execute("SELECT force_logout FROM users WHERE username=? AND role IN ('user','professor')", (username,))
                result = cur.fetchone()
                if result and result[0] == 1:
                    # Reset force_logout flag (important!)
                    cur.execute("UPDATE users SET force_logout = 0 WHERE username=?", (username,))
                    cur.execute("DELETE FROM active_sessions WHERE student_id=?", (username,))
                    conn.commit()
                    return jsonify({'force_logout': True})
        return jsonify({'force_logout': False})
    except Exception as e:
        print(f"Error in /api/check_logout: {e}")
        return jsonify({'error': str(e)}), 500, {'ContentType': 'application/json'}

@app.route('/upload_cropped_profile', methods=['POST'])
def upload_cropped_profile():
    user_id = session.get('id')

    img = request.files['croppedImage']

    try:
        # Open image via Pillow
        image = Image.open(io.BytesIO(img.read()))
        if image.mode in ("RGBA", "P"):
            image = image.convert("RGB")

        # Upload folder
        upload_folder = os.path.join(app.root_path, 'static', 'profiles')
        os.makedirs(upload_folder, exist_ok=True)

        filename = f"profile_{user_id}.png"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image.save(filepath)

        # Update database
        update_profile_picture('/static/uploads/' + filename)

        return jsonify({'success': True, 'image_url': '/static/uploads/' + filename})

    except Exception as e:
        print(f"Error saving image: {e}")
        return jsonify({'success': False, 'message': str(e)})
def update_profile_picture(filepath):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET profile_pic=? WHERE username=?",
                (filepath, session["username"] )
            )
            conn.commit()
        return True
    except Exception as e:
        print("DB update error:", e)
        return False




# ============================================================
# ============================================================
# STEP 2: SCAN DEVICES + AUTO REGISTER + EMBEDDED PHYSICAL SCANNER
# Fixed by ChatGPT
# Goal:
# - Do NOT run DETECTIONAGENT/AnomalyPerDevice/Peripherals_detection.py anymore.
# - Run only this app.py.
# - Detect only actual plugged physical devices.
# - Do not show every Windows HID/driver child entry.
# - Keep connected, unplugged, missing, faulty, and replaced logic.
# ============================================================

import json
import subprocess
import threading

EMBEDDED_AGENT_INTERVAL_SECONDS = 1
FAULTY_RECONNECT_COUNT = 15
MISSING_THRESHOLD_SECONDS = 60

ALLOWED_EMBEDDED_DEVICE_TYPES = {
    "Mouse",
    "Keyboard",
    "Headset",
    "Earphone",
    "Printer",
    "Monitor"
}


def ensure_detected_devices_table():
    """
    Creates detected_devices table if it does not exist yet.
    This table is used by the Scan Devices button.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS detected_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id TEXT NOT NULL,
                pc_tag TEXT NOT NULL,
                unique_id TEXT NOT NULL,
                name TEXT,
                device_type TEXT,
                vendor TEXT,
                product TEXT,
                serial_number TEXT,
                status TEXT DEFAULT 'connected',
                last_seen TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(lab_id, pc_tag, unique_id)
            )
        """)

        conn.commit()
        conn.close()
        print("[EMBEDDED AGENT] detected_devices table ready.")

    except Exception as e:
        print("[EMBEDDED TABLE ERROR]", e)


def normalize_scanned_device_type(device_type):
    """
    Converts scanned device type into the same style used by peripherals.name.
    """
    if not device_type:
        return "Unknown"

    text = str(device_type).lower().strip()

    if "mouse" in text:
        return "Mouse"
    if "keyboard" in text:
        return "Keyboard"
    if "printer" in text or "print" in text:
        return "Printer"
    if "monitor" in text or "display" in text:
        return "Monitor"
    if "headset" in text:
        return "Headset"
    if "earphone" in text or "earbud" in text or "headphone" in text:
        return "Earphone"

    return "Unknown"


# Alias used by the embedded scanner.
embedded_normalize_device_type = normalize_scanned_device_type


def embedded_device_type_candidates(device_type):
    normalized = embedded_normalize_device_type(device_type)

    if normalized in ["Headset", "Earphone"]:
        return ["Headset", "Earphone", "Headphone", "Headphones"]

    return [normalized]


def embedded_classify_device_type(name, pnp_class=None):
    """
    Classify only inventory-level device types.
    """
    text = f"{name or ''} {pnp_class or ''}".lower()

    if "mouse" in text or "mice" in text or "pointing" in text:
        return "Mouse"
    if "keyboard" in text:
        return "Keyboard"
    if "printer" in text or "print" in text:
        return "Printer"
    if "monitor" in text or "display" in text or "generic pnp monitor" in text:
        return "Monitor"
    if "headset" in text:
        return "Headset"
    if (
        "earphone" in text
        or "earbud" in text
        or "earbuds" in text
        or "headphone" in text
        or "headphones" in text
    ):
        return "Earphone"

    return "Unknown"


def embedded_extract_vendor_product_from_pnp_id(pnp_id):
    vendor = None
    product = None
    serial_number = None

    if not pnp_id:
        return vendor, product, serial_number

    parts = str(pnp_id).split("\\")

    for part in parts:
        upper_part = part.upper()

        if "VID_" in upper_part:
            try:
                vendor = upper_part.split("VID_")[1].split("&")[0]
            except Exception:
                pass

        if "PID_" in upper_part:
            try:
                product = upper_part.split("PID_")[1].split("&")[0]
            except Exception:
                pass

    if len(parts) >= 3:
        serial_number = parts[-1]

    return vendor, product, serial_number


def embedded_is_noise_device(name, instance_id, pnp_class):
    """
    Skip hubs, controllers, virtual devices, and generic child drivers.
    We still allow actual mouse/keyboard class entries before grouping.
    """
    text = f"{name or ''} {instance_id or ''} {pnp_class or ''}".lower()

    noise_keywords = [
        "root hub",
        "generic usb hub",
        "usb hub",
        "host controller",
        "usb controller",
        "bluetooth",
        "virtual",
        "software device",
        "system control",
        "consumer control",
        "vendor-defined",
        "hid-compliant vendor-defined",
        "composite bus",
        "enumerator",
        "root\\",
        "acpi\\",
        "swd\\",
        "bth\\",
        "display audio",
        "audio endpoint",
        "microphone array",
        "speakers (",
        "digital audio",
    ]

    return any(keyword in text for keyword in noise_keywords)


def embedded_run_powershell_usb_scan():
    """
    Gets present PnP device entries that may be actual inventory devices.

    Important fix:
    Windows creates several HID/driver child entries for one mouse or keyboard.
    This query also gets ContainerId, then Python groups by ContainerId so
    only one physical device appears in the Inventory Scan Devices list.
    """
    powershell_script = r"""
    $items = Get-PnpDevice -PresentOnly |
        Where-Object {
            $_.Status -eq "OK" -and
            (
                $_.Class -eq "Mouse" -or
                $_.Class -eq "Keyboard" -or
                $_.Class -eq "Printer" -or
                $_.Class -eq "Monitor" -or
                $_.InstanceId -like "USB\VID_*" -or
                $_.InstanceId -like "HID\VID_*" -or
                $_.InstanceId -like "USBPRINT\*" -or
                $_.InstanceId -like "DISPLAY\*" -or
                $_.FriendlyName -match "(?i)mouse|keyboard|printer|monitor|display|headset|headphone|headphones|earphone|earbud|earbuds"
            )
        }

    $out = foreach ($d in $items) {
        $container = $null
        try {
            $prop = Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction SilentlyContinue
            if ($prop) { $container = [string]$prop.Data }
        } catch {}

        [PSCustomObject]@{
            Name = $d.FriendlyName
            PNPDeviceID = $d.InstanceId
            Manufacturer = $d.Manufacturer
            PNPClass = $d.Class
            Status = $d.Status
            ContainerId = $container
        }
    }

    $out | ConvertTo-Json -Depth 5
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                powershell_script
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print("[EMBEDDED SCAN ERROR]", result.stderr)
            return []

        output = result.stdout.strip()

        if not output:
            print("[EMBEDDED SCAN] No present physical device candidates found.")
            return []

        parsed = json.loads(output)

        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return parsed

        return []

    except Exception as e:
        print("[EMBEDDED SCAN ERROR]", e)
        return []


def embedded_pick_best_name(items, device_type):
    """
    Pick a readable physical device name from grouped PnP entries.
    Avoid names like USB Input Device or HID-compliant mouse if a better name exists.
    """
    generic_words = [
        "hid-compliant",
        "usb input device",
        "input device",
        "consumer control",
        "vendor-defined",
        "composite device",
    ]

    names = []
    for item in items:
        name = item.get("Name") or ""
        if name and name not in names:
            names.append(name)

    # Prefer names that are not generic Windows driver labels.
    for name in names:
        lower_name = name.lower()
        if not any(word in lower_name for word in generic_words):
            return name

    # If everything is generic, show clean inventory type instead of driver text.
    return device_type


def embedded_get_connected_devices():
    """
    Returns one row per actual plugged physical inventory device.

    This fixes the bug where Windows shows many child drivers for one device.
    Example: one mouse may appear as USB Input Device, HID-compliant mouse,
    consumer control, etc. We group these by ContainerId.
    """
    raw_devices = embedded_run_powershell_usb_scan()
    grouped = {}

    for raw in raw_devices:
        name = raw.get("Name")
        pnp_id = raw.get("PNPDeviceID")
        pnp_class = raw.get("PNPClass")
        container_id = raw.get("ContainerId")

        if not pnp_id:
            continue

        if embedded_is_noise_device(name, pnp_id, pnp_class):
            continue

        # ContainerId means actual physical device group.
        # If missing, use PNPDeviceID as fallback.
        group_key = str(container_id or pnp_id).strip()

        if not group_key:
            continue

        grouped.setdefault(group_key, []).append(raw)

    cleaned_devices = []
    seen_unique_ids = set()

    for group_key, items in grouped.items():
        combined_names = " ".join(str(item.get("Name") or "") for item in items)
        combined_classes = " ".join(str(item.get("PNPClass") or "") for item in items)

        device_type = embedded_classify_device_type(combined_names, combined_classes)

        if device_type not in ALLOWED_EMBEDDED_DEVICE_TYPES:
            continue

        # Choose best instance id only for vendor/product extraction.
        best_instance_id = None
        for item in items:
            candidate = item.get("PNPDeviceID") or ""
            upper_candidate = candidate.upper()
            if "VID_" in upper_candidate or "PID_" in upper_candidate:
                best_instance_id = candidate
                break

        if not best_instance_id:
            best_instance_id = items[0].get("PNPDeviceID")

        # unique_id should represent the physical plugged device.
        # ContainerId is stable per physical device group and prevents duplicate driver rows.
        unique_id = str(group_key).strip()

        if not unique_id or unique_id in seen_unique_ids:
            continue

        seen_unique_ids.add(unique_id)

        vendor, product, _ = embedded_extract_vendor_product_from_pnp_id(best_instance_id)
        name = embedded_pick_best_name(items, device_type)
        manufacturer = next((item.get("Manufacturer") for item in items if item.get("Manufacturer")), "Unknown")

        cleaned_devices.append({
            "unique_id": unique_id,
            "name": name,
            "device_type": device_type,
            "vendor": vendor or manufacturer or "Unknown",
            "product": product or "Unknown",
            "serial_number": unique_id
        })

    return cleaned_devices


def embedded_identify_current_pc():
    """
    Finds this current PC from devices table using hostname.
    This allows many labs and many PCs.
    """
    hostname = socket.gethostname()

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT id, tag, location, comlab_id, hostname
            FROM devices
            WHERE LOWER(hostname) = LOWER(?)
            LIMIT 1
        """, (hostname,))

        row = cur.fetchone()
        conn.close()

        if not row:
            print(f"[EMBEDDED AGENT] Hostname not registered in devices table: {hostname}")
            return None, None

        lab_id = row["comlab_id"] if row["comlab_id"] else row["location"]
        pc_tag = row["tag"]

        return str(lab_id), pc_tag

    except Exception as e:
        print("[EMBEDDED IDENTIFY ERROR]", e)
        return None, None


def embedded_get_active_user(cur, pc_tag):
    cur.execute("""
        SELECT student_name, student_id
        FROM active_sessions
        WHERE pc_tag = ?
        LIMIT 1
    """, (pc_tag,))

    row = cur.fetchone()

    if row:
        return row[0] or "", row[1] or ""

    return "", ""


def embedded_alert_exists(cur, serial_number, alert_type):
    cur.execute("""
        SELECT id
        FROM peripheral_alerts
        WHERE serial_number = ?
          AND alert_type = ?
          AND deleted = 0
        LIMIT 1
    """, (serial_number, alert_type))

    return cur.fetchone() is not None


def embedded_insert_alert_once(cur, serial_number, alert_type, timestamp, device_name, location, event_type, device_type, user_id=None):
    if embedded_alert_exists(cur, serial_number, alert_type):
        return

    cur.execute("""
        INSERT INTO peripheral_alerts
        (serial_number, alert_type, timestamp, device_name, location, event_type, device_type, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        serial_number,
        alert_type,
        timestamp,
        device_name,
        location,
        event_type,
        device_type,
        user_id
    ))


def embedded_insert_usb_event(cur, event_type, device, pc_tag, lab_id):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username, user_id = embedded_get_active_user(cur, pc_tag)

    cur.execute("""
        INSERT INTO usb_devices
        (event_type, device_type, vendor, product, unique_id, username, timestamp, pc_tag, user_id, device_name, location)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        embedded_normalize_device_type(device.get("device_type")),
        device.get("vendor") or "Unknown",
        device.get("product") or "Unknown",
        device.get("unique_id"),
        username,
        timestamp,
        pc_tag,
        user_id,
        pc_tag,
        str(lab_id)
    ))

    return timestamp, user_id


def embedded_log_peripheral_event(cur, unique_id, event_type, device_type, pc_tag):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO peripheral_logs
        (unique_id, event_type, device_type, timestamp, device_name)
        VALUES (?, ?, ?, ?, ?)
    """, (
        unique_id,
        event_type,
        embedded_normalize_device_type(device_type),
        timestamp,
        pc_tag
    ))

    return timestamp


def embedded_count_cycles(cur, unique_id):
    cur.execute("""
        SELECT event_type
        FROM peripheral_logs
        WHERE unique_id = ?
          AND datetime(timestamp) >= datetime('now', '-10 minutes')
        ORDER BY datetime(timestamp) ASC
    """, (unique_id,))

    events = [row[0] for row in cur.fetchall()]
    cycle_count = 0

    for i in range(len(events) - 1):
        if events[i] == "connected" and events[i + 1] == "disconnected":
            cycle_count += 1

    return cycle_count


def embedded_find_registered_by_type(cur, lab_id, pc_tag, device_type):
    candidates = embedded_device_type_candidates(device_type)
    placeholders = ",".join(["?"] * len(candidates))

    cur.execute(f"""
        SELECT id, name, serial_number, unique_id, status
        FROM peripherals
        WHERE lab_id = ?
          AND assigned_pc = ?
          AND LOWER(name) IN ({','.join(['LOWER(?)'] * len(candidates))})
        LIMIT 1
    """, [str(lab_id), pc_tag] + candidates)

    return cur.fetchone()


def embedded_process_connected_event(cur, lab_id, pc_tag, device):
    """
    Runs once when a physical device becomes connected.
    Handles connected, replaced, and faulty.
    """
    unique_id = device.get("unique_id")
    device_type = embedded_normalize_device_type(device.get("device_type"))
    now, user_id = embedded_insert_usb_event(cur, "connected", device, pc_tag, lab_id)
    embedded_log_peripheral_event(cur, unique_id, "connected", device_type, pc_tag)

    registered = embedded_find_registered_by_type(cur, lab_id, pc_tag, device_type)

    if registered:
        peripheral_id, registered_name, registered_serial, registered_unique, old_status = registered
        registered_id = registered_serial or registered_unique

        if registered_id == unique_id:
            cur.execute("""
                UPDATE peripherals
                SET status = ?
                WHERE id = ?
            """, ("connected", peripheral_id))
        else:
            cur.execute("""
                UPDATE peripherals
                SET status = ?
                WHERE id = ?
            """, ("replaced", peripheral_id))

            embedded_insert_alert_once(
                cur,
                unique_id,
                "replaced",
                now,
                pc_tag,
                str(lab_id),
                "connected",
                device_type,
                user_id
            )

    cycle_count = embedded_count_cycles(cur, unique_id)

    if cycle_count >= FAULTY_RECONNECT_COUNT:
        cur.execute("""
            UPDATE peripherals
            SET status = ?
            WHERE serial_number = ?
               OR unique_id = ?
        """, ("faulty", unique_id, unique_id))

        embedded_insert_alert_once(
            cur,
            unique_id,
            "faulty",
            now,
            pc_tag,
            str(lab_id),
            "connected",
            device_type,
            user_id
        )


def embedded_process_disconnected_event(cur, lab_id, pc_tag, device):
    """
    Runs once when a physical device becomes unplugged.
    This updates the registered peripheral row immediately to unplugged.
    """
    unique_id = device.get("unique_id")
    device_type = embedded_normalize_device_type(device.get("device_type"))

    if not unique_id:
        return

    now, _ = embedded_insert_usb_event(cur, "disconnected", device, pc_tag, lab_id)
    embedded_log_peripheral_event(cur, unique_id, "disconnected", device_type, pc_tag)

    cur.execute("""
        SELECT id, name, serial_number, unique_id
        FROM peripherals
        WHERE lab_id = ?
          AND assigned_pc = ?
          AND (serial_number = ? OR unique_id = ?)
        LIMIT 1
    """, (str(lab_id), pc_tag, unique_id, unique_id))

    registered = cur.fetchone()

    if not registered:
        print(f"[UNPLUGGED WARNING] No registered peripheral matched {unique_id} on {pc_tag} Lab {lab_id}")
        return

    peripheral_id, registered_name, registered_serial, registered_unique = registered
    registered_id = registered_serial or registered_unique or unique_id

    cur.execute("""
        UPDATE peripherals
        SET status = 'unplugged'
        WHERE id = ?
    """, (peripheral_id,))

    print(f"[STATUS UPDATE] {pc_tag} | {registered_name} | unplugged")

    cycle_count = embedded_count_cycles(cur, registered_id)

    if cycle_count >= FAULTY_RECONNECT_COUNT:
        cur.execute("""
            UPDATE peripherals
            SET status = 'faulty'
            WHERE id = ?
        """, (peripheral_id,))

        _, user_id = embedded_get_active_user(cur, pc_tag)
        embedded_insert_alert_once(
            cur,
            registered_id,
            "faulty",
            now,
            pc_tag,
            str(lab_id),
            "disconnected",
            registered_name,
            user_id
        )


def embedded_check_missing_devices(cur, lab_id, pc_tag):
    """
    Registered device becomes missing if it has been unplugged for 1 minute.
    """
    cur.execute("""
        SELECT id, name, serial_number, unique_id, status
        FROM peripherals
        WHERE lab_id = ?
          AND assigned_pc = ?
          AND LOWER(status) = 'unplugged'
    """, (str(lab_id), pc_tag))

    rows = cur.fetchall()

    for peripheral_id, device_name, serial_number, unique_id, status in rows:
        registered_id = serial_number or unique_id

        cur.execute("""
            SELECT timestamp
            FROM peripheral_logs
            WHERE unique_id = ?
              AND event_type = 'disconnected'
            ORDER BY datetime(timestamp) DESC
            LIMIT 1
        """, (registered_id,))

        last_unplug = cur.fetchone()

        if not last_unplug:
            continue

        try:
            last_unplug_time = datetime.strptime(last_unplug[0], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue

        if (datetime.now() - last_unplug_time).total_seconds() >= MISSING_THRESHOLD_SECONDS:
            cur.execute("""
                UPDATE peripherals
                SET status = ?
                WHERE id = ?
            """, ("missing", peripheral_id))

            _, user_id = embedded_get_active_user(cur, pc_tag)

            embedded_insert_alert_once(
                cur,
                registered_id,
                "missing",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                pc_tag,
                str(lab_id),
                "disconnected",
                device_name,
                user_id
            )


def embedded_save_detected_devices_and_update_status(lab_id, pc_tag, devices):
    """
    Saves current scan to detected_devices and updates status logic.

    Only newly connected/disconnected physical devices generate logs.
    This prevents duplicate logs every 5 seconds.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
            SELECT unique_id, name, device_type, vendor, product, serial_number
            FROM detected_devices
            WHERE lab_id = ?
              AND pc_tag = ?
              AND status = 'connected'
        """, (str(lab_id), pc_tag))

        previous_connected = {
            row[0]: {
                "unique_id": row[0],
                "name": row[1],
                "device_type": row[2],
                "vendor": row[3],
                "product": row[4],
                "serial_number": row[5]
            }
            for row in cur.fetchall()
        }

        current_connected = {}

        for dev in devices:
            unique_id = dev.get("unique_id")
            if not unique_id:
                continue

            dev["device_type"] = embedded_normalize_device_type(dev.get("device_type"))
            dev["serial_number"] = unique_id
            current_connected[unique_id] = dev

        # Save connected devices.
        for unique_id, dev in current_connected.items():
            device_type = dev.get("device_type")

            cur.execute("""
                INSERT INTO detected_devices
                (lab_id, pc_tag, unique_id, name, device_type, vendor, product, serial_number, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'connected', ?)
                ON CONFLICT(lab_id, pc_tag, unique_id)
                DO UPDATE SET
                    name = excluded.name,
                    device_type = excluded.device_type,
                    vendor = excluded.vendor,
                    product = excluded.product,
                    serial_number = excluded.serial_number,
                    status = 'connected',
                    last_seen = excluded.last_seen
            """, (
                str(lab_id),
                pc_tag,
                unique_id,
                dev.get("name") or device_type,
                device_type,
                dev.get("vendor") or "Unknown",
                dev.get("product") or "Unknown",
                unique_id,
                now
            ))

            # Process only if newly connected.
            if unique_id not in previous_connected:
                embedded_process_connected_event(cur, lab_id, pc_tag, dev)

        # Process devices that disappeared from current physical scan.
        disconnected_ids = set(previous_connected.keys()) - set(current_connected.keys())

        for unique_id in disconnected_ids:
            old_dev = previous_connected[unique_id]

            cur.execute("""
                UPDATE detected_devices
                SET status = 'unplugged', last_seen = ?
                WHERE lab_id = ?
                  AND pc_tag = ?
                  AND unique_id = ?
            """, (now, str(lab_id), pc_tag, unique_id))

            embedded_process_disconnected_event(cur, lab_id, pc_tag, old_dev)

        embedded_check_missing_devices(cur, lab_id, pc_tag)

        conn.commit()
        conn.close()

        print(f"[EMBEDDED AGENT] {pc_tag} | Lab {lab_id} | Connected physical devices: {len(current_connected)}")

    except Exception as e:
        print("[EMBEDDED SAVE/STATUS ERROR]", e)


@app.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    """
    Optional compatibility endpoint.
    You do not need to run Peripherals_detection.py anymore.
    """
    data = request.get_json(silent=True) or {}

    lab_id = data.get("lab_id")
    pc_tag = data.get("pc_tag")
    devices = data.get("devices", [])

    if not lab_id or not pc_tag:
        return jsonify({
            "success": False,
            "message": "lab_id and pc_tag are required."
        }), 400

    ensure_detected_devices_table()
    embedded_save_detected_devices_and_update_status(lab_id, pc_tag, devices)

    return jsonify({
        "success": True,
        "message": "Heartbeat saved.",
        "device_count": len(devices)
    })


@app.route("/api/scan_devices", methods=["GET"])
def scan_devices():
    """
    Called by inventory.html when clicking Scan Devices.
    It does a live physical scan, then returns only connected physical devices.
    """
    lab_id = request.args.get("lab_id")
    pc_tag = request.args.get("pc_tag")

    if not lab_id or not pc_tag:
        return jsonify({
            "success": False,
            "message": "lab_id and pc_tag are required."
        }), 400

    try:
        ensure_detected_devices_table()

        live_devices = embedded_get_connected_devices()

        print(f"[LIVE SCAN] Requested PC: {pc_tag} | Lab: {lab_id}")
        print(f"[LIVE SCAN] Found physical devices: {len(live_devices)}")

        for device in live_devices:
            print("[LIVE SCAN DEVICE]", device)

        embedded_save_detected_devices_and_update_status(lab_id, pc_tag, live_devices)

        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT
                id,
                lab_id,
                pc_tag,
                unique_id,
                name,
                device_type,
                vendor,
                product,
                serial_number,
                status,
                last_seen
            FROM detected_devices
            WHERE lab_id = ?
              AND pc_tag = ?
              AND status = 'connected'
            ORDER BY datetime(last_seen) DESC
        """, (str(lab_id), pc_tag))

        devices = [dict(row) for row in cur.fetchall()]
        conn.close()

        return jsonify({
            "success": True,
            "devices": devices
        })

    except Exception as e:
        print("[SCAN DEVICES ERROR]", e)
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/api/register_scanned_peripheral", methods=["POST"])
def register_scanned_peripheral():
    """
    Registers selected physical scanned device into peripherals.
    """
    data = request.get_json(silent=True) or {}

    lab_id = data.get("lab_id")
    pc_tag = data.get("pc_tag")
    unique_id = data.get("unique_id")
    device_type = normalize_scanned_device_type(data.get("device_type"))
    brand = data.get("brand") or data.get("vendor") or "Unknown"
    remarks = data.get("remarks") or ""

    if not lab_id or not pc_tag or not unique_id:
        return jsonify({
            "success": False,
            "message": "lab_id, pc_tag, and unique_id are required."
        }), 400

    if not device_type or device_type == "Unknown":
        return jsonify({
            "success": False,
            "message": "Device type is required."
        }), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
            SELECT id
            FROM devices
            WHERE tag = ?
              AND location = ?
            LIMIT 1
        """, (pc_tag, str(lab_id)))

        pc_exists = cur.fetchone()

        if not pc_exists:
            conn.close()
            return jsonify({
                "success": False,
                "message": f"PC '{pc_tag}' not found in ComLab {lab_id}."
            }), 404

        cur.execute("""
            SELECT assigned_pc, lab_id, name
            FROM peripherals
            WHERE unique_id = ?
               OR serial_number = ?
            LIMIT 1
        """, (unique_id, unique_id))

        existing_unique = cur.fetchone()

        if existing_unique:
            existing_pc = existing_unique[0]
            existing_lab = existing_unique[1]
            existing_name = existing_unique[2]

            conn.close()
            return jsonify({
                "success": False,
                "message": f"This {existing_name} is already registered to Lab {existing_lab} - {existing_pc}."
            }), 409

        candidates = embedded_device_type_candidates(device_type)
        placeholders = ",".join(["LOWER(?)"] * len(candidates))

        cur.execute(f"""
            SELECT id
            FROM peripherals
            WHERE assigned_pc = ?
              AND lab_id = ?
              AND LOWER(name) IN ({placeholders})
            LIMIT 1
        """, [pc_tag, str(lab_id)] + candidates)

        existing_type = cur.fetchone()

        if existing_type:
            conn.close()
            return jsonify({
                "success": False,
                "message": f"{pc_tag} already has a registered {device_type}."
            }), 409

        cur.execute("""
            INSERT INTO peripherals
            (name, brand, unique_id, serial_number, status, remarks, lab_id, assigned_pc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_type,
            brand,
            unique_id,
            unique_id,
            "connected",
            remarks,
            str(lab_id),
            pc_tag
        ))

        conn.commit()
        peripheral_id = cur.lastrowid
        conn.close()

        return jsonify({
            "success": True,
            "message": f"{device_type} registered successfully to {pc_tag}.",
            "peripheral": {
                "id": peripheral_id,
                "name": device_type,
                "brand": brand,
                "unique_id": unique_id,
                "serial_number": unique_id,
                "status": "connected",
                "remarks": remarks,
                "lab_id": lab_id,
                "assigned_pc": pc_tag
            }
        })

    except sqlite3.Error as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/api/agent/identify_pc", methods=["GET"])
def agent_identify_pc():
    hostname = request.args.get("hostname", "").strip()

    if not hostname:
        return jsonify({
            "success": False,
            "message": "hostname is required."
        }), 400

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT id, tag, location, comlab_id, hostname
        FROM devices
        WHERE LOWER(hostname) = LOWER(?)
        LIMIT 1
    """, (hostname,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({
            "success": False,
            "message": f"This PC hostname '{hostname}' is not registered in devices table."
        }), 404

    lab_id = row["comlab_id"] if row["comlab_id"] else row["location"]

    return jsonify({
        "success": True,
        "hostname": row["hostname"],
        "pc_tag": row["tag"],
        "lab_id": lab_id
    })


@app.route("/api/peripheral_statuses/<int:comlab_id>")
def api_peripheral_statuses(comlab_id):
    """
    Used by inventory.html to refresh status pills without reloading the page.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT id, name, assigned_pc, status, remarks
            FROM peripherals
            WHERE lab_id = ?
        """, (str(comlab_id),))

        peripherals = [dict(row) for row in cur.fetchall()]
        conn.close()

        return jsonify({
            "success": True,
            "peripherals": peripherals
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500



def embedded_detection_loop():
    print("[EMBEDDED AGENT] Starting physical device scanner...")
    ensure_detected_devices_table()

    while True:
        lab_id, pc_tag = embedded_identify_current_pc()

        if lab_id and pc_tag:
            devices = embedded_get_connected_devices()
            embedded_save_detected_devices_and_update_status(lab_id, pc_tag, devices)

            for d in devices:
                print("[PHYSICAL DEVICE]", d["device_type"], "|", d["name"], "|", d["unique_id"])
        else:
            print("[EMBEDDED AGENT] PC not identified. Register this PC first.")

        time.sleep(EMBEDDED_AGENT_INTERVAL_SECONDS)


def start_embedded_detection_agent():
    thread = threading.Thread(target=embedded_detection_loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    start_embedded_detection_agent()
    app.run(debug=True, use_reloader=False)
