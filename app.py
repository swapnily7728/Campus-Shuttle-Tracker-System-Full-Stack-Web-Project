# app.py
# Main application file for the Campus Shuttle Tracker System.

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import requests
import random
from datetime import datetime, timedelta, date, time
import uuid # For generating unique pass IDs
from sqlalchemy import func
from werkzeug.utils import secure_filename

# --- App Initialization and Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_me' # IMPORTANT: Change this key
project_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(project_dir, 'shuttle_tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(project_dir, 'static', 'uploads')
db = SQLAlchemy(app)

# --- Ensure upload folder exists ---
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- 2Factor.in API Configuration ---
# IMPORTANT: PASTE YOUR API KEY HERE FOR OTPs TO WORK ON YOUR PHONE
TWO_FACTOR_API_KEY = '80388e90-1931-11f0-8b17-0200cd936042'

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False) # In a real app, hash this!
    role = db.Column(db.String(20), nullable=False, default='User')
    payments = db.relationship('Payment', backref='user', lazy=True)
    bus_pass = db.relationship('BusPass', backref='user', uselist=False)
    attendance_records = db.relationship('Attendance', backref='user', lazy=True)
    bus = db.relationship('Bus', backref='driver', uselist=False)
    fastag_requests = db.relationship('FastagRechargeRequest', backref='driver', lazy=True)
    refuel_requests = db.relationship('RefuelRequest', backref='driver', lazy=True)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=500.0)
    payment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)

class BusPass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    pass_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    issue_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    check_in_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Bus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bus_number = db.Column(db.String(20), unique=True, nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=True)
    current_fuel = db.Column(db.Float, default=100.0)
    latitude = db.Column(db.Float, default=18.5204) # Default to Pune, India
    longitude = db.Column(db.Float, default=73.8567)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    fastag_requests = db.relationship('FastagRechargeRequest', backref='bus', lazy=True)
    refuel_requests = db.relationship('RefuelRequest', backref='bus', lazy=True)

# NEW: Request Models
class FastagRechargeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    current_balance = db.Column(db.Float, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending') # Pending, Approved, Rejected

class RefuelRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    fuel_amount = db.Column(db.Float, nullable=False)
    fuel_cost = db.Column(db.Float, nullable=False)
    refuel_date = db.Column(db.Date, nullable=False)
    refuel_time = db.Column(db.Time, nullable=False)
    odometer_reading = db.Column(db.Integer, nullable=False)
    receipt_filename = db.Column(db.String(255), nullable=True)
    remarks = db.Column(db.Text, nullable=True)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending') # Pending, Approved, Rejected

# --- Helper Functions ---
def send_otp(phone_number):
    """Sends an OTP. Simulates if API key is missing."""
    if TWO_FACTOR_API_KEY == 'YOUR_2FACTOR_API_KEY_HERE':
        otp = str(random.randint(1000, 9999))
        session['otp'] = otp
        print(f"!!! SIMULATED OTP for {phone_number}: {otp} !!!")
        return True
    url = f"https://2factor.in/API/V1/{TWO_FACTOR_API_KEY}/SMS/{phone_number}/AUTOGEN"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get('Status') == 'Success':
            session['otp_session_id'] = data.get('Details')
            return True
        else:
            flash(f"Failed to send OTP: {data.get('Details')}", 'danger')
            return False
    except requests.RequestException as e:
        flash(f'An error occurred while sending OTP: {e}', 'danger')
        return False

def verify_otp(session_id, otp):
    """Verifies an OTP. Simulates if API key is missing."""
    if TWO_FACTOR_API_KEY == 'YOUR_2FACTOR_API_KEY_HERE':
        return session.get('otp') == otp
    if not session_id:
        flash('OTP session not found. Please try logging in again.', 'danger')
        return False
    url = f"https://2factor.in/API/V1/{TWO_FACTOR_API_KEY}/SMS/VERIFY/{session_id}/{otp}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get('Status') == 'Success'
    except requests.RequestException:
        flash('An error occurred while verifying OTP.', 'danger')
        return False

# --- Global & Main Routes ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = User.query.get(user_id) if user_id else None

@app.route('/')
def index():
    bus_count = Bus.query.count()
    active_users = User.query.filter_by(role='User').count()
    return render_template('index.html', bus_count=bus_count, active_users=active_users)

# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        existing_user = User.query.filter_by(phone_number=request.form['phone_number']).first()
        if existing_user:
            flash('A user with this phone number already exists.', 'warning')
            return redirect(url_for('register'))
        user = User(full_name=request.form['full_name'], phone_number=request.form['phone_number'], password=request.form['password'], role=request.form['role'])
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(phone_number=request.form['phone_number']).first()
        if user and user.password == request.form['password']:
            if send_otp(user.phone_number):
                session['phone_for_verification'] = user.phone_number
                return redirect(url_for('verify_otp_route'))
            return redirect(url_for('login'))
        else:
            flash('Invalid phone number or password.', 'danger')
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    if 'phone_for_verification' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        if verify_otp(session.get('otp_session_id'), request.form['otp']):
            user = User.query.filter_by(phone_number=session['phone_for_verification']).first()
            session.clear()
            session['user_id'] = user.id
            session['user_role'] = user.role
            g.user = user
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_otp.html')

@app.route('/logout')
def logout():
    session.clear()
    g.user = None
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Role-based Access Decorator ---
def role_required(role):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            allowed_roles = role if isinstance(role, list) else [role]
            if g.user is None or g.user.role not in allowed_roles:
                flash('Access denied. You do not have the required permissions.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Dashboard Route ---
@app.route('/dashboard')
@role_required(['Admin', 'Driver', 'User'])
def dashboard():
    if g.user.role == 'Admin':
        buses = Bus.query.all()
        fuel_labels = [bus.bus_number for bus in buses]
        fuel_data = [bus.current_fuel for bus in buses]
        today = date.today()
        seven_days_ago = today - timedelta(days=6)
        attendance_data = db.session.query(func.date(Attendance.check_in_time), func.count(Attendance.id)).filter(func.date(Attendance.check_in_time) >= seven_days_ago).group_by(func.date(Attendance.check_in_time)).all()
        attendance_dict = {entry[0].strftime("%Y-%m-%d"): entry[1] for entry in attendance_data}
        attendance_labels = [(today - timedelta(days=i)).strftime("%a, %b %d") for i in range(6, -1, -1)]
        attendance_counts = [attendance_dict.get((today - timedelta(days=i)).strftime("%Y-%m-%d"), 0) for i in range(6, -1, -1)]
        pending_requests = FastagRechargeRequest.query.filter_by(status='Pending').count() + RefuelRequest.query.filter_by(status='Pending').count()
        return render_template('admin_dashboard.html', fuel_labels=fuel_labels, fuel_data=fuel_data, attendance_labels=attendance_labels, attendance_counts=attendance_counts, pending_requests=pending_requests)
    return render_template('dashboard.html', user=g.user)

# --- USER FEATURE ROUTES ---
@app.route('/fee-payment', methods=['GET', 'POST'])
@role_required('User')
def fee_payment():
    if request.method == 'POST':
        new_payment = Payment(user_id=g.user.id, transaction_id=f"txn_{uuid.uuid4()}")
        db.session.add(new_payment)
        db.session.commit()
        flash('Payment successful!', 'success')
        return redirect(url_for('payment_success', trans_id=new_payment.transaction_id))
    return render_template('fee_payment.html')

@app.route('/payment-success')
@role_required('User')
def payment_success():
    trans_id = request.args.get('trans_id')
    payment = Payment.query.filter_by(transaction_id=trans_id, user_id=g.user.id).first_or_404()
    return render_template('payment_success.html', payment=payment)

@app.route('/pass-generation')
@role_required('User')
def pass_generation():
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    last_payment = Payment.query.filter(Payment.user_id == g.user.id, Payment.payment_date >= thirty_days_ago).order_by(Payment.payment_date.desc()).first()
    existing_pass = g.user.bus_pass
    if existing_pass and existing_pass.expiry_date > datetime.utcnow():
        return render_template('pass_generation.html', bus_pass=existing_pass)
    if not last_payment:
        flash('You must pay the fee before generating a pass.', 'warning')
        return redirect(url_for('fee_payment'))
    expiry_date = last_payment.payment_date + timedelta(days=30)
    if existing_pass:
        existing_pass.issue_date = datetime.utcnow()
        existing_pass.expiry_date = expiry_date
        flash('Your bus pass has been renewed successfully!', 'success')
    else:
        existing_pass = BusPass(user_id=g.user.id, expiry_date=expiry_date)
        db.session.add(existing_pass)
        flash('Your bus pass has been generated successfully!', 'success')
    db.session.commit()
    return render_template('pass_generation.html', bus_pass=existing_pass)

@app.route('/attendance', methods=['GET', 'POST'])
@role_required('User')
def attendance():
    bus_pass = g.user.bus_pass
    pass_is_valid = bus_pass and bus_pass.expiry_date > datetime.utcnow()
    if request.method == 'POST':
        if not pass_is_valid:
            flash('Your bus pass is not valid. Please pay the fee to renew it.', 'danger')
        else:
            today_start = datetime.utcnow().date()
            last_check_in = Attendance.query.filter(Attendance.user_id == g.user.id, db.func.date(Attendance.check_in_time) == today_start).first()
            if last_check_in:
                flash(f"You have already checked in today at {last_check_in.check_in_time.strftime('%I:%M %p')}.", 'info')
            else:
                db.session.add(Attendance(user_id=g.user.id))
                db.session.commit()
                flash('Checked in successfully!', 'success')
        return redirect(url_for('attendance'))
    attendance_history = Attendance.query.filter_by(user_id=g.user.id).order_by(Attendance.check_in_time.desc()).limit(30).all()
    return render_template('attendance.html', history=attendance_history, pass_valid=pass_is_valid)

# --- ADMIN & DRIVER ROUTES ---
@app.route('/location-tracking')
@role_required(['Admin', 'Driver'])
def location_tracking():
    return render_template('location_tracking.html', title="Bus Location Tracking")

@app.route('/manage-buses')
@role_required('Admin')
def manage_buses():
    buses = Bus.query.all()
    assigned_driver_ids = [bus.driver_id for bus in buses if bus.driver_id]
    unassigned_drivers = User.query.filter(User.role == 'Driver', User.id.notin_(assigned_driver_ids)).all()
    return render_template('manage_buses.html', buses=buses, unassigned_drivers=unassigned_drivers)

@app.route('/add-bus', methods=['POST'])
@role_required('Admin')
def add_bus():
    bus_number = request.form.get('bus_number')
    if bus_number and not Bus.query.filter_by(bus_number=bus_number).first():
        db.session.add(Bus(bus_number=bus_number))
        db.session.commit()
        flash(f'Bus {bus_number} added successfully.', 'success')
    else:
        flash('Invalid bus number or bus already exists.', 'danger')
    return redirect(url_for('manage_buses'))

@app.route('/assign-driver', methods=['POST'])
@role_required('Admin')
def assign_driver():
    bus_id = request.form.get('bus_id')
    driver_id = request.form.get('driver_id')
    bus = Bus.query.get(bus_id)
    if bus and driver_id:
        bus.driver_id = driver_id
        db.session.commit()
        flash('Driver assigned successfully.', 'success')
    else:
        flash('Failed to assign driver.', 'danger')
    return redirect(url_for('manage_buses'))

# --- NEW: Driver Request Routes ---
@app.route('/request-fastag-recharge', methods=['GET', 'POST'])
@role_required('Driver')
def request_fastag_recharge():
    driver_bus = g.user.bus
    if not driver_bus:
        flash('You are not assigned to a bus. Cannot make a request.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_request = FastagRechargeRequest(
            driver_id=g.user.id,
            bus_id=driver_bus.id,
            current_balance=float(request.form['current_balance']),
            reason=request.form['reason']
        )
        db.session.add(new_request)
        db.session.commit()
        flash('FASTag recharge request submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('request_fastag_recharge.html', bus=driver_bus)

@app.route('/request-refuel', methods=['GET', 'POST'])
@role_required('Driver')
def request_refuel():
    driver_bus = g.user.bus
    if not driver_bus:
        flash('You are not assigned to a bus. Cannot make a request.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        receipt_file = request.files['receipt']
        filename = None
        if receipt_file:
            filename = secure_filename(receipt_file.filename)
            receipt_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_request = RefuelRequest(
            driver_id=g.user.id,
            bus_id=driver_bus.id,
            fuel_amount=float(request.form['fuel_amount']),
            fuel_cost=float(request.form['fuel_cost']),
            refuel_date=datetime.strptime(request.form['refuel_date'], '%Y-%m-%d').date(),
            refuel_time=datetime.strptime(request.form['refuel_time'], '%H:%M').time(),
            odometer_reading=int(request.form['odometer_reading']),
            receipt_filename=filename,
            remarks=request.form['remarks']
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Refuel request submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('request_refuel.html', bus=driver_bus)

# --- NEW: Admin Request Management Routes ---
@app.route('/view-requests')
@role_required('Admin')
def view_requests():
    fastag_reqs = FastagRechargeRequest.query.order_by(FastagRechargeRequest.request_date.desc()).all()
    refuel_reqs = RefuelRequest.query.order_by(RefuelRequest.request_date.desc()).all()
    return render_template('view_requests.html', fastag_requests=fastag_reqs, refuel_requests=refuel_reqs)

@app.route('/handle-request/<req_type>/<int:req_id>', methods=['POST'])
@role_required('Admin')
def handle_request(req_type, req_id):
    action = request.form.get('action') # 'Approve' or 'Reject'
    if not action:
        flash('Invalid action.', 'danger')
        return redirect(url_for('view_requests'))

    if req_type == 'fastag':
        req = FastagRechargeRequest.query.get_or_404(req_id)
    elif req_type == 'refuel':
        req = RefuelRequest.query.get_or_404(req_id)
    else:
        flash('Invalid request type.', 'danger')
        return redirect(url_for('view_requests'))

    req.status = action
    db.session.commit()
    flash(f'Request has been {action.lower()}ed.', 'success')
    return redirect(url_for('view_requests'))

# --- API ENDPOINT ---
@app.route('/api/bus-locations')
def bus_locations():
    if not g.user or g.user.role not in ['Admin', 'Driver']:
        return jsonify({"error": "Unauthorized"}), 403
    buses = Bus.query.all()
    locations = []
    for bus in buses:
        bus.latitude += random.uniform(-0.0005, 0.0005)
        bus.longitude += random.uniform(-0.0005, 0.0005)
        bus.last_updated = datetime.utcnow()
        locations.append({
            "id": bus.id, "bus_number": bus.bus_number, "lat": bus.latitude, "lng": bus.longitude,
            "driver": bus.driver.full_name if bus.driver else "N/A", "fuel": bus.current_fuel,
            "updated": bus.last_updated.strftime("%I:%M:%S %p")
        })
    db.session.commit()
    return jsonify(locations)

# --- DUMMY DATA CREATION ---
def create_dummy_data():
    with app.app_context():
        if Bus.query.count() == 0:
            print("Creating dummy buses...")
            buses_data = [
                {'bus_number': 'MH-12-AB-1234', 'current_fuel': 80.5, 'latitude': 18.5250, 'longitude': 73.8490},
                {'bus_number': 'MH-14-CD-5678', 'current_fuel': 65.0, 'latitude': 18.5180, 'longitude': 73.8580},
                {'bus_number': 'MH-12-EF-9012', 'current_fuel': 95.2, 'latitude': 18.5220, 'longitude': 73.8600}
            ]
            for data in buses_data:
                db.session.add(Bus(**data))
            db.session.commit()
        if User.query.filter_by(role='Admin').count() == 0:
             print("Creating dummy admin...")
             db.session.add(User(full_name="Admin User", phone_number="9000000001", password="admin", role="Admin"))
             db.session.commit()
        if User.query.filter_by(role='Driver').count() == 0:
             print("Creating dummy drivers...")
             drivers_data = [
                 {'full_name': 'Ravi Kumar', 'phone_number': '9284099340', 'password': 'driver', 'role': 'Driver'},
                 {'full_name': 'Suresh Patel', 'phone_number': '9000000003', 'password': 'driver', 'role': 'Driver'}
            ]
             for data in drivers_data:
                db.session.add(User(**data))
             db.session.commit()

# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_dummy_data()
    app.run(debug=True)