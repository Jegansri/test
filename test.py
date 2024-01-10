# Import standard libraries
import os
import json
import io
import base64
from io import BytesIO
import random
import string
import logging
import time
from datetime import datetime

# Import third-party libraries
from dotenv import load_dotenv
import requests
import pyAesCrypt
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for, send_from_directory, make_response, send_file, session
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_cors import CORS
from pyotp import TOTP, random_base32
from jwt import decode, InvalidTokenError
from requests.adapters import HTTPAdapter
import qrcode
from requests.packages.urllib3.exceptions import SubjectAltNameWarning

# Disable SSL warning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY_ENV_VAR')
ENCRYPTION_PASSWORD = os.getenv('ENCRYPTION_PASSWORD_ENV_VAR')
CSP_DEFAULT_SRC = os.getenv('CSP_DEFAULT_SRC')
CSP_IMG_SRC = os.getenv('CSP_IMG_SRC')
CSP_SCRIPT_SRC = os.getenv('CSP_SCRIPT_SRC')
CSP_STYLE_SRC = os.getenv('CSP_STYLE_SRC')
KEYCLOAK_REALM_INFO_URL = os.getenv('KEYCLOAK_REALM_INFO_URL')
CERT_PATH = os.getenv('CERT_PATH')
ISSUER_URL = os.getenv('KEYCLOAK_ISSUER')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
RECAPTCHA_VERIFY_URL = os.getenv('RECAPTCHA_VERIFY_URL')
# Check environment variables
if not SECRET_KEY:
    raise ValueError("Please set the SECRET_KEY_ENV_VAR environment variable")
if not ENCRYPTION_PASSWORD:
    raise ValueError("Please set the ENCRYPTION_PASSWORD_ENV_VAR environment variable")

# Application and logging configuration
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['UPLOAD_FOLDER'] = 'uploads'
CORS(app, supports_credentials=True)

if not CSP_DEFAULT_SRC or not CSP_IMG_SRC or not CSP_SCRIPT_SRC or not CSP_STYLE_SRC:
    raise ValueError("CSP environment variables are not set properly!")

# Convert environment variable string values to lists
CSP_DEFAULT_SRC = CSP_DEFAULT_SRC.split()
CSP_IMG_SRC = CSP_IMG_SRC.split()
CSP_SCRIPT_SRC = CSP_SCRIPT_SRC.split()
CSP_STYLE_SRC = CSP_STYLE_SRC.split()
CSP_CONNECT_SRC = os.getenv('CSP_CONNECT_SRC').split(' ')
CSP_FRAME_SRC = os.getenv('CSP_FRAME_SRC').split()
# CSP Configuration
csp = {
    'default-src': CSP_DEFAULT_SRC,
    'img-src': CSP_IMG_SRC,
    'script-src': CSP_SCRIPT_SRC + ['nonce'],  # Ensure you have 'nonce' here
    'style-src': CSP_STYLE_SRC + ['nonce'],   # Ensure you have 'nonce' here
    'connect-src': CSP_CONNECT_SRC,
    'frame-src': CSP_FRAME_SRC,
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src']
)
def csp_nonce():
    return request.csp_nonce  # This is automatically added by Flask-Talisman

app.jinja_env.globals.update(csp_nonce=csp_nonce)  # Make the function available to Jinja2 templates

# Database setup
db = SQLAlchemy(app)

# Login Manager setup
login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    secret = db.Column(db.String(500), nullable=True)

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/get_keycloak_config')
def get_keycloak_config():
    with open('/root/templates/keycloak.json', 'r') as f:
        config = json.load(f)
    return jsonify(config)

@app.route('/')
def index():
    logging.info('Visited the index route')
    return render_template('loginqr31_recaptcha_v5.html')

@app.route('/get_keycloak_json', methods=['GET'])
def get_keycloak_json():
    return send_from_directory(app.static_folder, 'keycloak.json')

@app.route('/set_user_directory', methods=['POST'])
def set_user_directory():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token = auth_header.split(" ")[1]
        decoded_token = verify_token(token)

        if not decoded_token:
            logging.warning('Invalid token attempt for set_user_directory endpoint')
            return jsonify({"error": "Invalid Token!"}), 401

        username = decoded_token.get('sub')
        user = User.query.filter_by(name=username).first()
        if not user:
            logging.info(f"Creating new user with name: {username}")
            user = User(name=username, secret=None)  # Initialize secret as None
            db.session.add(user)
            db.session.commit()

        login_user(user)

        if user.secret is not None:  # Check for None instead of if user.secret
            return jsonify({"totp_setup": True})
        else:
            return jsonify({"totp_setup": False})
    else:
        logging.warning('Missing token for set_user_directory endpoint')
        return jsonify({"error": "Missing Token!"}), 401



# Encryption and Decryption Utilities

BUFFER_SIZE = 64 * 1024

def encrypt_data(data):
    plaintext_stream = BytesIO(data.encode('utf-8'))
    ciphertext_stream = BytesIO()

    pyAesCrypt.encryptStream(plaintext_stream, ciphertext_stream, ENCRYPTION_PASSWORD, BUFFER_SIZE)
    logging.info('TOTP Secret encrypted successfully.')
    return base64.b64encode(ciphertext_stream.getvalue()).decode('utf-8')

def decrypt_data(encrypted_data):
    encrypted_stream = BytesIO(base64.b64decode(encrypted_data))
    decrypted_stream = BytesIO()

    pyAesCrypt.decryptStream(encrypted_stream, decrypted_stream, ENCRYPTION_PASSWORD, BUFFER_SIZE, len(encrypted_data))
    logging.info('TOTP Secret decrypted successfully.')
    return decrypted_stream.getvalue().decode('utf-8')


@app.route("/totp-setup", methods=["GET", "POST"])
def totp_setup():
    if request.method == "POST":
        totp_code = request.form.get('totp_code')
        secret_decrypted = decrypt_data(current_user.secret)
        totp = TOTP(secret_decrypted)
        if totp.verify(totp_code):
            logging.info(f"User {current_user.name} successfully verified TOTP code.")
            return redirect(url_for('protected'))
        else:
            logging.warning(f"User {current_user.name} provided an invalid TOTP code.")
            flash("Invalid TOTP code. Please try again.", "error")
            return redirect(url_for('totp_setup'))

    if current_user.secret is None:
        secret = random_base32()
        encrypted_secret = encrypt_data(secret)
        current_user.secret = encrypted_secret
        db.session.commit()
        logging.info(f"New secret generated and encrypted for user: {current_user.name}")
    else:
        secret = decrypt_data(current_user.secret)

    qr_uri = TOTP(secret).provisioning_uri(name=current_user.name, issuer_name="YourApp")
    img = qrcode.make(qr_uri)
    stream = BytesIO()
    img.save(stream, "PNG")
    stream.seek(0)
    img_b64 = base64.b64encode(stream.getvalue()).decode('utf-8')
    return render_template("totp_setup21.html", img_b64=img_b64)


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    if request.method == "POST":
        totp_code = request.form.get('totp_code')
        secret_decrypted = decrypt_data(current_user.secret)
        totp = TOTP(secret_decrypted)
        if totp.verify(totp_code):
            logging.info(f"User {current_user.name} successfully verified TOTP code during verification.")
            return redirect(url_for('protected'))
        else:
            logging.warning(f"User {current_user.name} provided an invalid TOTP code during verification.")
            flash("Invalid TOTP code. Please try again.", "error")
            return redirect(url_for('verify_totp'))
    return render_template("verify_totp21.html")

# Global variables
CACHED_PUBLIC_KEY = None
LAST_FETCHED_TIMESTAMP = 0  # Timestamp when the public key was last fetched
KEY_REFRESH_INTERVAL = 3600  # Refresh interval in seconds (1 hour in this case)

def get_public_key_from_keycloak(force_refresh=False):
    global CACHED_PUBLIC_KEY, LAST_FETCHED_TIMESTAMP

    # Check if the public key is cached and if it needs to be refreshed
    current_timestamp = int(time.time())
    if CACHED_PUBLIC_KEY and not force_refresh and (current_timestamp - LAST_FETCHED_TIMESTAMP) < KEY_REFRESH_INTERVAL:
        logging.info("Using cached public key.")
        return CACHED_PUBLIC_KEY

    # Either the key is not cached or it needs to be refreshed
    if not KEYCLOAK_REALM_INFO_URL or not CERT_PATH:
        logging.error("Environment variables KEYCLOAK_REALM_INFO_URL or CERT_PATH are not set")
        return None

    class HostnameIgnoringAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs['assert_hostname'] = False
            return super(HostnameIgnoringAdapter, self).init_poolmanager(*args, **kwargs)

    s = requests.Session()
    s.mount('https://', HostnameIgnoringAdapter())

    try:
        response = s.get(KEYCLOAK_REALM_INFO_URL, verify=CERT_PATH)
        response.raise_for_status()
        data = response.json()
        public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{data['public_key']}\n-----END PUBLIC KEY-----"

        # Update the cached public key and the last fetched timestamp
        CACHED_PUBLIC_KEY = public_key_pem
        LAST_FETCHED_TIMESTAMP = current_timestamp
        logging.info("Public key retrieved and cached.")

        return public_key_pem
    except Exception as e:
        logging.error(f"Error retrieving the public key: {str(e)}")
        return None

def verify_token(token):
    public_key = get_public_key_from_keycloak()

    if not public_key or not ISSUER_URL:
        logging.error("Public key or ISSUER_URL is not available")
        return None

    try:
        decoded_token = decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_aud": False},
            issuer=ISSUER_URL
        )
        logging.info("Token successfully verified.")
        return decoded_token
    except InvalidTokenError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        logging.warning(f"Failed token: {token}")  # Log the invalid token
        return None

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    try:
        # Check if the user is authenticated before proceeding
        if current_user.is_authenticated:
            username = current_user.name  # Store username before logging out for logging purposes
            logout_user()
            logging.info(f"User {username} logged out successfully.")
            return jsonify({'message': 'Logged out'}), 200
        else:
            logging.warning("Unauthorized logout attempt detected.")
            return jsonify({'error': 'Unauthorized'}), 401  # Return an unauthorized status code
    except Exception as e:
        # Log any unexpected errors that occur during the process
        logging.error(f"An error occurred during logout: {str(e)}")
        return jsonify({'error': 'An error occurred while processing the logout request'}), 500

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/protected', methods=['GET', 'POST'])
@login_required
def protected():
    # Create a directory path using the user's ID
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.name)

    try:
        # Ensure the directory exists
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            logging.info(f"Directory created or verified for user {current_user.name}: {user_dir}")
    except Exception as e:
        logging.error(f"Error creating directory {user_dir}: {e}")
        # Log or print errors related to directory creation


    # Pagination logic
    PAGE_SIZE = 10
    page = int(request.args.get('page', 1))
    start_idx = (page - 1) * PAGE_SIZE
    end_idx = start_idx + PAGE_SIZE

    all_files = sorted(os.listdir(user_dir))
    files = all_files[start_idx:end_idx]
    total_pages = (len(all_files) + PAGE_SIZE - 1) // PAGE_SIZE  # Calculate the total number of pages

    if request.method == 'POST':
        uploaded_files = request.files.getlist('file')
        for file in uploaded_files:
            if file and file.filename:
                filepath = os.path.join(user_dir, file.filename)
                file.save(filepath)
                logging.info(f"File {file.filename} uploaded by user {current_user.name}")

                # Encrypt the file after saving
                temp_filepath = filepath + ".temp"
                pyAesCrypt.encryptFile(filepath, temp_filepath, ENCRYPTION_PASSWORD, BUFFER_SIZE)  # Corrected this line
                os.remove(filepath)
                os.rename(temp_filepath, filepath)
                logging.info(f"File {file.filename} encrypted for user {current_user.name}")

            # Re-fetch the file list (this is the key part)
            all_files = sorted(os.listdir(user_dir))
            files = all_files[start_idx:end_idx]
            total_pages = (len(all_files) + PAGE_SIZE - 1) // PAGE_SIZE

    return render_template('auth2fav1_dataprivacy.html', files=files, current_page=page, total_pages=total_pages)

@app.route('/protected/delete', methods=['POST'])
def protected_delete_files():
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.name)

    files_to_delete = request.form.getlist('files_to_delete')
    for file in files_to_delete:
        file_path = os.path.join(user_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f"Deleted {file}", "success")
            logging.info(f"User {current_user.name} deleted file: {file}")
        else:
            flash(f"Error deleting {file}", "error")
            logging.warning(f"User {current_user.name} attempted to delete a non-existing file: {file}")
    return redirect(url_for('protected'))

@app.route('/protected/download/<filename>', methods=['GET'])
def protected_download_file(filename):
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.name)

    encrypted_filepath = os.path.join(user_dir, filename)
    if not os.path.exists(encrypted_filepath):
        flash("File does not exist.", "error")
        logging.warning(f"User {current_user.name} tried to download a non-existing file: {filename}")
        return redirect(url_for('protected'))

    file_size = os.path.getsize(encrypted_filepath)

    with open(encrypted_filepath, 'rb') as f_encrypted:
        decrypted_data = BytesIO()
        try:
            pyAesCrypt.decryptStream(f_encrypted, decrypted_data, ENCRYPTION_PASSWORD, BUFFER_SIZE, file_size)  # Corrected this line
        except ValueError:
            flash("Decryption error. Invalid password or corrupted file.", "error")
            logging.error(f"Decryption error for user {current_user.name} while trying to download file: {filename}")
            return redirect(url_for('protected'))

        decrypted_data.seek(0)
        logging.info(f"User {current_user.name} successfully downloaded file: {filename}")
        return send_file(decrypted_data, as_attachment=True, download_name=filename)

    # Default return in case all other conditions fail
    logging.error(f"Unknown error occurred for user {current_user.name} while downloading file: {filename}")
    flash("Unknown error occurred while downloading the file.", "error")
    return redirect(url_for('protected'))

@app.route('/verify-recaptcha', methods=['POST'])
def verify_recaptcha():
    # Extract token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or "Bearer" not in auth_header:
        logging.warning("No Authorization header or Bearer token provided in request.")
        return jsonify(success=False, error="No Bearer token provided."), 401
    token = auth_header.split(" ")[1]
    decoded_token = verify_token(token)

    if not decoded_token:
        logging.warning('Invalid token attempt for /verify-recaptcha endpoint')
        return jsonify(success=False, error="Invalid Token!"), 401

    username = decoded_token.get('sub')

    # Extract token data from request JSON
    recaptcha_token = request.json.get('recaptcha_token')
    if not recaptcha_token:
        logging.warning(f"User {username}: No recaptcha_token provided in request.")
        return jsonify(success=False, error="No recaptcha_token provided."), 400

    # Set up the data for reCAPTCHA API call
    data = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_token
    }

    # Make the API call
    verification_response = requests.post(RECAPTCHA_VERIFY_URL, data=data)
    verification_data = verification_response.json()

    if verification_data.get('success'):
        score = verification_data.get('score')
        logging.info(f"User {username}: Successfully verified reCAPTCHA. Score: {score}")
        return jsonify(success=True, score=score)
    else:
        error_message = 'Failed to verify reCAPTCHA.'
        logging.error(f"User {username}: {error_message}")
        return jsonify(success=False, error=error_message), 400

@app.route('/log-recaptcha-score', methods=['POST'])
def log_recaptcha_score():
    # Extract token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or "Bearer" not in auth_header:
        logging.warning("No Authorization header or Bearer token provided in request.")
        return jsonify(success=False, error="No Bearer token provided."), 401
    token = auth_header.split(" ")[1]
    decoded_token = verify_token(token)

    if not decoded_token:
        logging.warning('Invalid token attempt for /log-recaptcha-score endpoint')
        return jsonify(success=False, error="Invalid Token!"), 401

    username = decoded_token.get('sub')

    # Extract score from request JSON
    recaptcha_score = request.json.get('recaptcha_score')
    if not recaptcha_score:
        logging.warning(f"User {username}: No recaptcha_score provided in request.")
        return jsonify(success=False, error="No recaptcha_score provided."), 400

    # Log the score (or handle it however you prefer)
    logging.info(f"User {username}: reCAPTCHA score received: {recaptcha_score}")

    return jsonify(success=True, message="reCAPTCHA score logged successfully.")

@app.route('/log-ip-country', methods=['POST'])
def log_ip_country():
    # Extract token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or "Bearer" not in auth_header:
        logging.warning("No Authorization header or Bearer token provided in request.")
        return jsonify(success=False, error="No Bearer token provided."), 401

    token = auth_header.split(" ")[1]
    decoded_token = verify_token(token)

    if not decoded_token:
        logging.warning('Invalid token attempt for /log-ip-country endpoint')
        return jsonify(success=False, error="Invalid Token!"), 401

    user_id = decoded_token.get('sub')  # Using 'sub' from the decoded token as the user identifier

    ip = request.json.get('ip')
    country = request.json.get('country')

    if not all([user_id, ip, country]):
        logging.warning(f"Incomplete data received for /log-ip-country. User ID: {user_id}, IP: {ip}, Country: {country}")
        return jsonify(success=False, error="Incomplete data provided."), 400

    # Log the data (or handle it however you prefer)
    logging.info(f"User ID {user_id}: IP - {ip}, Country - {country}")

    return jsonify(success=True, message="IP and Country logged successfully.")


# Application entry point
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(threaded=True, debug=False, host='127.0.0.1', port=5001)
