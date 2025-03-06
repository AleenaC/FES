from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from io import BytesIO
import base64
import secrets

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database configuration

# Initialize database
db = SQLAlchemy(app)

# Generate RSA key pair (store securely in a real application)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize keys (you would normally store and load these securely)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# User model to store registered users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each user
    username = db.Column(db.String(50), unique=True, nullable=False)  # Unique username
    password = db.Column(db.String(200), nullable=False)  # Hashed password

# File model to store encrypted files
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique file ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key linking to User
    filename = db.Column(db.String(100), nullable=False)  # Original filename
    encrypted_data = db.Column(db.LargeBinary, nullable=False)  # AES Encrypted file data
    encrypted_key = db.Column(db.LargeBinary, nullable=False)  # RSA Encrypted AES key
    iv = db.Column(db.LargeBinary, nullable=False)

# AES encryption helper functions
def encrypt_file_aes(data):
    aes_key = secrets.token_bytes(32)  # Generate random AES key
    iv = secrets.token_bytes(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = data + b' ' * (16 - len(data) % 16)  # Pad data to 16-byte blocks
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encrypt AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data, encrypted_key, iv

def decrypt_file_aes(encrypted_data, encrypted_key, iv):
    # Decrypt AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.rstrip(b' ')  # Remove padding

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # Hash the password
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))  # Redirect to login page after registration
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):  # Verify password
            session['user_id'] = user.id  # Store user session
            return redirect(url_for('dashboard'))
    return render_template('login.html')

# Dashboard route where users can upload files
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']  # Get uploaded file
        encrypted_data, encrypted_key, iv = encrypt_file_aes(file.read())
        new_file = File(user_id=session['user_id'], filename=file.filename, encrypted_data=encrypted_data, encrypted_key=encrypted_key, iv=iv)
        db.session.add(new_file)
        db.session.commit()
    files = File.query.filter_by(user_id=session['user_id']).all()  # Fetch all user files
    return render_template('dashboard.html', files=files)

# Route to download and decrypt files
@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file = File.query.get(file_id)
    if file and file.user_id == session['user_id']:
        decrypted_data = decrypt_file_aes(file.encrypted_data, file.encrypted_key,file.iv)
        return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=file.filename)  # Send file
    return redirect(url_for('dashboard'))

# Route to log out the user
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user session
    return redirect(url_for('login'))

# Main execution point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they do not exist
    app.run(debug=True)  # Run Flask app in debug mode
