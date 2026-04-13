import os
from dotenv import load_dotenv
load_dotenv()  # Load .env file

# --- STABILITY ANCHOR (APPLE SILICON) ---
# We must disable GPU before any other modules load Tensorflow
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import tensorflow as tf
try:
    tf.config.set_visible_devices([], 'GPU')
except:
    pass

import uuid
import json
import sqlite3
import hashlib
import re
import traceback
from datetime import timedelta, datetime
from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify

from security import encrypt_data, decrypt_data
from heatmap import generate_heatmap
from predict_pneumonia import predict_pneumonia
from predict_fracture import predict_fracture
from sentinel_engine import SentinelEngine
from policy_engine import PolicyEngine

# --- SENTINEL PROTOCOL (SP) INITIALIZATION ---
SENTINEL = SentinelEngine()
POLICY = PolicyEngine()
AUDIT_QUEUE = [] # Buffer for Merkle Batching

# Hugging Face AI Integration
from huggingface_hub import InferenceClient

# PDF libs
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import qrcode, io

app = Flask(__name__)
# Secure Secret Key for Session Management
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "xray_ai_fallback_key_129847")

# ---------------- CONFIG ----------------
app.permanent_session_lifetime = timedelta(minutes=30)
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
DB = "medical.db"
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_MODEL = "openai/gpt-oss-120b"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ---------------- DATABASE INIT ----------------
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data TEXT,
                current_hash TEXT,
                previous_hash TEXT,
                timestamp TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS security_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                timestamp TEXT
            )
        """)

        # --- SENTINEL PROTOCOL TABLES ---
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT,
                prev_hash TEXT,
                current_hash TEXT,
                timestamp TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS signature_vault (
                user_id TEXT PRIMARY KEY,
                pub_key TEXT,
                encrypted_share_b TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS patient_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_name TEXT,
                age TEXT,
                gender TEXT,
                scan_type TEXT,
                result TEXT,
                confidence REAL,
                xray_path TEXT,
                heatmap_path TEXT,
                block_hash TEXT,
                pdf_path TEXT,
                assigned_doctor_id TEXT,
                timestamp TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS prescriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prescription_id TEXT UNIQUE,
                patient_name TEXT,
                doctor_name TEXT,
                diagnosis TEXT,
                encrypted_medicines TEXT,
                encrypted_instructions TEXT,
                block_hash TEXT,
                status TEXT DEFAULT 'active',
                timestamp TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS pharmacy_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                category TEXT,
                description TEXT,
                price REAL,
                stock INTEGER,
                requires_prescription INTEGER,
                image_url TEXT,
                manufacturer TEXT
            )
        """)

        # --- MULTI-DOCTOR IDENTITY TABLE ---
        c.execute("""
            CREATE TABLE IF NOT EXISTS doctors (
                id TEXT PRIMARY KEY,
                name TEXT,
                password TEXT,
                specialization TEXT
            )
        """)

        # Seed doctors if they don't exist
        c.execute("SELECT COUNT(*) FROM doctors")
        if c.fetchone()[0] == 0:
            doctors_list = [
                ('abhay', 'Dr. Abhay', 'abhay123', 'Diagnostic Lead'),
                ('sarah', 'Dr. Sarah', 'sarah456', 'Pulmonology Specialist'),
                ('mike', 'Dr. Mike', 'mike789', 'Radiology Expert')
            ]
            c.executemany("INSERT INTO doctors (id, name, password, specialization) VALUES (?,?,?,?)", doctors_list)
            print("SENTINEL: Doctors seeded successfully.")

        conn.commit()

# Run initialization on startup
init_db()

# ----------- HUGGING FACE AI ADVISORY -----------
def get_hf_client():
    """Create HF InferenceClient if token is available."""
    if not HF_TOKEN:
        return None
    try:
        return InferenceClient(model=HF_MODEL, token=HF_TOKEN)
    except:
        return None

# ---------------- SECURITY ----------------
def log_intrusion(action):
    ip = request.remote_addr
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO security_logs (ip, action, timestamp) VALUES (?,?,?)",
                  (ip, action, time))
        conn.commit()
    
    # Also log to immutable ledger
    log_to_ledger(f"INTRUSION_ALERT: {action} (IP: {ip})")

def log_to_ledger(event_text):
    """Adds a record to the immutable hash-chained audit ledger."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        
        # Get last hash
        c.execute("SELECT current_hash FROM audit_ledger ORDER BY id DESC LIMIT 1")
        last_row = c.fetchone()
        prev_hash = last_row[0] if last_row else "0" * 64
        
        # New hash
        current_hash = hashlib.sha256(f"{prev_hash}{event_text}{timestamp}".encode()).hexdigest()
        
        c.execute("INSERT INTO audit_ledger (event, prev_hash, current_hash, timestamp) VALUES (?,?,?,?)",
                  (event_text, prev_hash, current_hash, timestamp))
        conn.commit()
        
        # Anchor to file system (Double Anchorage)
        with open("sentinel_anchor.txt", "a") as f:
            f.write(f"{timestamp} | {current_hash}\n")

# ---------------- PHARMACY SEEDING ----------------
def seed_pharmacy():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM pharmacy_products")
        if c.fetchone()[0] > 0:
            return

        products = [
            ("Amoxicillin 500mg", "antibiotic", "Broad-spectrum penicillin antibiotic for general infections.", 12.50, 150, 1, "💊", "BioPharma"),
            ("Azithromycin 250mg", "antibiotic", "Macrolide antibiotic used for respiratory and skin infections.", 18.20, 100, 1, "💊", "HealthCare Inc."),
            ("Ciprofloxacin 500mg", "antibiotic", "Fluoroquinolone antibiotic for severe bacterial infections including UTI and pneumonia.", 15.75, 80, 1, "💊", "AstraGenix"),
            ("Ibuprofen 400mg", "painkiller", "NSAID for pain relief, inflammation reduction and fever management.", 6.99, 300, 0, "💊", "PainFree Co."),
            ("Paracetamol 500mg", "painkiller", "Acetaminophen for mild to moderate pain and fever. Safe for most patients.", 4.50, 500, 0, "💊", "SafeMed Labs"),
            ("Salbutamol Inhaler", "respiratory", "Bronchodilator inhaler for asthma and COPD. Provides rapid breathing relief.", 22.00, 75, 1, "🫁", "BreathEasy Inc."),
            ("Calcium + Vitamin D3", "bone_health", "Essential supplement for bone strength. Prevents osteoporosis and fractures.", 11.50, 250, 0, "🦴", "BoneStrong"),
            ("Vitamin C 1000mg", "supplement", "Immune system booster. High-potency ascorbic acid for daily immune support.", 7.99, 400, 0, "💎", "VitaPlus"),
        ]

        c.executemany("""
            INSERT INTO pharmacy_products
            (name, category, description, price, stock, requires_prescription, image_url, manufacturer)
            VALUES (?,?,?,?,?,?,?,?)
        """, products)
        conn.commit()

seed_pharmacy()

# ---------------- LOGIN & LOGOUT ----------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role")
        password = request.form.get("password")
        form_next = request.form.get("next_url")

        if role == "doctor":
            with sqlite3.connect(DB) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM doctors WHERE (name=? OR id=?) AND password=?", 
                          (request.form.get("name"), request.form.get("name"), password))
                doctor = c.fetchone()
                
                if not doctor:
                    log_intrusion(f"Failed doctor login attempt for: {request.form.get('name')}")
                    return "Invalid Doctor Credentials", 401
                
                session["name"] = doctor["name"]
                session["doc_id"] = doctor["id"]
        else:
            session["name"] = request.form.get("name")

        session.permanent = True
        session["age"] = request.form.get("age")
        session["gender"] = request.form.get("gender")
        session["role"] = role

        # --- SENTINEL PROTOCOL: DOCTOR KEY SHARD HANDLING ---
        if role == "doctor":
            doc_id = session["name"]
            with sqlite3.connect(DB) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM signature_vault WHERE user_id=?", (doc_id,))
                vault = c.fetchone()
                
                if not vault:
                    pub_key, shares = SENTINEL.generate_doctor_keys()
                    share_a = shares[0]
                    share_b_hex = shares[1][1]
                    
                    c.execute("INSERT INTO signature_vault (user_id, pub_key, encrypted_share_b) VALUES (?,?,?)",
                              (doc_id, pub_key.decode(), share_b_hex))
                    conn.commit()
                    
                    session["doc_key_share_a"] = share_a[1]
                else:
                    # In a real scenario, we'd recover the share. For now, we simulate.
                    pass

        log_to_ledger(f"USER_LOGIN: {session.get('name')} as {role}")
        
        red_url = form_next if form_next else ("/doctor" if role == "doctor" else "/patient")
        return redirect(red_url)

    next_url = request.args.get("next")
    return render_template("login.html", next_url=next_url)

@app.route("/logout")
def logout():
    log_to_ledger(f"USER_LOGOUT: {session.get('name')}")
    session.clear()
    return redirect("/")

# ---------------- PATIENT & DOCTOR DASHBOARD ----------------
@app.route("/patient")
def patient_landing():
    if session.get("role") != "patient":
        return redirect("/login")
    
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, specialization FROM doctors")
        doctors = [dict(r) for r in c.fetchall()]
        
    return render_template("chest.html", doctors=doctors)

@app.route("/doctor")
def doctor():
    if session.get("role") != "doctor":
        return redirect("/login")
    
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Privacy Firewall: Only see patients assigned to THIS doctor
        c.execute("SELECT * FROM patient_logs WHERE assigned_doctor_id=? ORDER BY id DESC", (session.get('doc_id'),))
        patients = c.fetchall()
        
        c.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 10")
        sec_logs = c.fetchall()
        
        c.execute("SELECT * FROM audit_ledger ORDER BY id DESC LIMIT 15")
        ledger = c.fetchall()
        
    return render_template("doctor.html", patients=patients, sec_logs=sec_logs, ledger=ledger)

# ---------------- DIAGNOSTIC LOGIC ----------------
@app.route("/chest")
def chest():
    if session.get("role") != "patient":
        return redirect("/login")
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, specialization FROM doctors")
        doctors = [dict(r) for r in c.fetchall()]
    return render_template("chest.html", doctors=doctors)

@app.route("/bone")
def bone():
    if session.get("role") != "patient":
        return redirect("/login")
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, specialization FROM doctors")
        doctors = [dict(r) for r in c.fetchall()]
    return render_template("bone.html", doctors=doctors)

@app.route("/predict", methods=["POST"])
def predict():
    current_role = session.get("role", "unknown")
    if current_role != "patient":
        log_intrusion(f"Unauthorized diagnostic attempt by {current_role}")
        return f"Access Denied: You are currently logged in as a '{current_role}'. Only Patients can perform diagnostic scans.", 403

    file = request.files.get("file")
    mode = request.form.get("mode") # 'chest' or 'bone'
    doc_id_assigned = request.form.get("doctor_id")

    if not file: return "Upload Error", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_{file.filename}")
    file.save(filepath)

    try:
        # 1. AI Analysis
        if mode == 'chest':
            disease, confidence = predict_pneumonia(filepath)
            target = "Chest"
        else:
            disease, confidence = predict_fracture(filepath)
            target = "Bone"

        # 2. XAI / Heatmap
        heatmap_path = filepath.split(".")[0] + "_heatmap.png"
        generate_heatmap(filepath, heatmap_path, mode)

        # 3. Cryptographic Anchoring
        block_hash = SENTINEL.anchor_diagnostic(session["name"], target, disease)
        
        # 4. Generate Sealed Report
        pdf_path = f"static/report_{uuid.uuid4().hex[:8]}.pdf"
        # (Mock PDF creation logic, I will restore the full report-gen module shortly)
        
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO patient_logs 
                (patient_name, age, gender, scan_type, result, confidence, xray_path, heatmap_path, block_hash, pdf_path, assigned_doctor_id, timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (session["name"], session["age"], session["gender"], target, disease, confidence, filepath, heatmap_path, block_hash, pdf_path, doc_id_assigned, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()

        log_to_ledger(f"DIAGNOSTIC_GENERATED: {target} for {session['name']} (Result: {disease})")

        # Fetch doctors for re-render
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, name, specialization FROM doctors")
            doctors = [dict(r) for r in c.fetchall()]

        template = "chest.html" if mode == 'chest' else "bone.html"
        return render_template(template, result=disease, confidence=round(confidence, 2), img=filepath, heatmap=heatmap_path, target=target, doctors=doctors)

    except Exception as e:
        traceback.print_exc()
        return f"Diagnostic Engine Error: {str(e)}", 500

# ---------------- PHARMACY / COMMERCE ----------------
@app.route("/pharmacy")
def pharmacy_home():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM pharmacy_products")
        products = c.fetchall()
    return render_template("pharmacy.html", products=products)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
