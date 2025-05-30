from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['CERT_FOLDER'] = 'certs'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['CERT_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted = db.Column(db.Boolean, default=False)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']

        # Prevent duplicate usernames
        if User.query.filter_by(username=username).first():
            return "Username already exists"

        # Create user
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        # If user is subscriber, generate certificate
        if role == 'subscriber':
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            cert_filename = f"{username}_key.pem"
            cert_path = os.path.join(app.config['CERT_FOLDER'], cert_filename)
            with open(cert_path, "wb") as f:
                f.write(private_key)

        # ✅ Redirect all users to login after signup
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/download_certificate/<filename>')
def download_certificate(filename):
    return send_from_directory(app.config['CERT_FOLDER'], filename, as_attachment=True)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    files = File.query.all()
    return render_template('dashboard.html', user=session['user'], role=session['role'], files=files)

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    file = request.files['file']
    if file:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(path)
        encrypted = True if request.form.get('encrypt') else False
        db.session.add(File(filename=file.filename, encrypted=encrypted))
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/uploads/<filename>')
def view_file(filename):
    file = File.query.filter_by(filename=filename).first()
    if file.encrypted and session.get('role') != 'subscriber':
        return "Unauthorized", 403
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/generate_certificate')
def generate_certificate():
    if 'user' not in session or session.get('role') != 'subscriber':
        return "Access denied", 403

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_path = os.path.join(app.config['CERT_FOLDER'], f"{session['user']}_key.pem")
    with open(cert_path, "wb") as f:
        f.write(private_key)

    return send_from_directory(app.config['CERT_FOLDER'], f"{session['user']}_key.pem", as_attachment=True)

def create_admin_user():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        hashed_pw = bcrypt.generate_password_hash("admin123").decode('utf-8')
        admin = User(username="admin", password=hashed_pw, role="admin")
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        create_admin_user()
    app.run(debug=True)
