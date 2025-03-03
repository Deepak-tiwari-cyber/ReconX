from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

import requests
import whois
import ipinfo
import shodan
import os
from dotenv import load_dotenv
import re
import json
import time
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

# Load API Keys and Config
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
IPINFO_ACCESS_TOKEN = os.getenv("IPINFO_ACCESS_TOKEN")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# New API Keys
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
HIBP_API_KEY = os.getenv('HIBP_API_KEY')
CENSYS_API_ID = os.getenv('CENSYS_API_ID')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')

# Initialize Flask App
app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per hour"]
)

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(120), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Drop all tables and create new ones
with app.app_context():
    db.drop_all()  # Drop all existing tables
    db.create_all()  # Create new tables
    
    # Create admin user if not exists
    if not User.query.filter_by(username=ADMIN_USERNAME).first():
        admin = User(
            username=ADMIN_USERNAME,
            is_admin=True,
            created_at=datetime.utcnow()
        )
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()

# Token Required Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            token = request.headers.get('X-API-Token')
        
        if not token:
            return {'message': 'Token is missing'}, 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return {'message': 'Token is invalid'}, 401

        return f(current_user, *args, **kwargs)
    return decorated

# Initialize APIs
shodan_api = shodan.Shodan(SHODAN_API_KEY)
ipinfo_handler = ipinfo.getHandler(IPINFO_ACCESS_TOKEN)

# WHOIS Lookup
def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Format the output nicely
        result = []
        for key, value in w.items():
            if value:
                if isinstance(value, (list, tuple)):
                    value = ', '.join(str(v) for v in value if v)
                result.append(f"{key}: {value}")
        return '\n'.join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Email Validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return "Email is valid."
    else:
        return "Invalid email format."

# Website Title Extraction
def get_website_title(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        # Use regex to extract title
        title_match = re.search('<title>(.*?)</title>', response.text, re.IGNORECASE)
        if title_match:
            return title_match.group(1)
        return "No title found"
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# IP Geolocation
def get_ip_geolocation(ip):
    try:
        details = ipinfo_handler.getDetails(ip)
        return details.all
    except ipinfo.exceptions.RequestQuotaExceededError:
        return "Error: API quota exceeded."
    except Exception as e:
        return f"Error: {str(e)}"

# Shodan API Scan
def get_shodan_scan(ip):
    try:
        host = shodan_api.host(ip)
        return host
    except shodan.APIError as e:
        return f"Error: {str(e)}"

def get_censys_data(domain):
    """Get domain information from Censys"""
    try:
        headers = {
            'Accept': 'application/json',
        }
        auth = (CENSYS_API_ID, CENSYS_API_SECRET)
        response = requests.get(
            f'https://search.censys.io/api/v2/hosts/search?q={domain}',
            headers=headers,
            auth=auth
        )
        if response.status_code == 200:
            return response.json()
        return "No Censys data available"
    except Exception as e:
        return f"Censys Error: {str(e)}"

def get_hibp_breaches(email):
    """Check if email has been involved in any breaches using HIBP"""
    try:
        headers = {
            'hibp-api-key': HIBP_API_KEY,
            'User-Agent': 'Recon-X-Tool'
        }
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return "No breaches found"
        return "Unable to check breaches"
    except Exception as e:
        return f"HIBP Error: {str(e)}"

def get_crt_subdomains(domain):
    """Get SSL certificate subdomains from crt.sh"""
    try:
        response = requests.get(f'https://crt.sh/?q=%.{domain}&output=json')
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([item['name_value'] for item in data]))
            return subdomains
        return "No subdomain data available"
    except Exception as e:
        return f"crt.sh Error: {str(e)}"

def get_virustotal_data(domain):
    """Get domain information from VirusTotal"""
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        return "No VirusTotal data available"
    except Exception as e:
        return f"VirusTotal Error: {str(e)}"

def get_wayback_urls(domain):
    """Get historical URLs from Wayback Machine"""
    try:
        response = requests.get(
            f'http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&collapse=urlkey'
        )
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # Skip header row
                urls = list(set([item[2] for item in data[1:]]))
                return urls[:100]  # Limit to 100 URLs
            return "No historical URLs found"
        return "No Wayback Machine data available"
    except Exception as e:
        return f"Wayback Machine Error: {str(e)}"

# Routes
@app.route("/", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def index():
    if request.method == "POST":
        if not current_user.is_active:
            flash("Your account has been deactivated")
            return redirect(url_for('login'))

        domain = request.form.get("domain", "").strip()
        email = request.form.get("email", "").strip()
        url = request.form.get("url", "").strip()
        ip = request.form.get("ip", "").strip()

        if not all([domain, email, url, ip]):
            return render_template("index.html", error="All fields are required")

        try:
            # Get all scan results
            whois_data = get_whois_data(domain)
            email_validation = validate_email(email)
            website_title = get_website_title(url)
            ip_geolocation = get_ip_geolocation(ip)
            shodan_scan = get_shodan_scan(ip)
            wayback_urls = get_wayback_urls(domain)

            # Store all results in session
            store_results_in_session(
                whois_data, email_validation, website_title, 
                ip_geolocation, shodan_scan, wayback_urls
            )

            return render_template("result.html",
                               whois_data=whois_data, 
                               email_validation=email_validation,
                               website_title=website_title,
                               ip_geolocation=ip_geolocation,
                               shodan_scan=shodan_scan,
                               wayback_urls=wayback_urls)
        except Exception as e:
            return render_template("index.html", error=f"Error: {str(e)}")

    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
            return render_template("register.html")

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash("Your account has been deactivated")
                return render_template("login.html")
                
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['SECRET_KEY'])
            session['token'] = token
            
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('token', None)
    return redirect(url_for('login'))

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))
    
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/admin/user/<int:user_id>/toggle")
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))
    
    user = User.query.get_or_404(user_id)
    if user.username == ADMIN_USERNAME:
        flash("Cannot modify admin user")
        return redirect(url_for("admin"))
    
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {user.username} {'activated' if user.is_active else 'deactivated'}")
    return redirect(url_for("admin"))

@app.route("/admin/user/<int:user_id>/delete")
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))
    
    user = User.query.get_or_404(user_id)
    if user.username == ADMIN_USERNAME:
        flash("Cannot delete admin user")
        return redirect(url_for("admin"))
    
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted")
    return redirect(url_for("admin"))

@app.route("/download_pdf", methods=["GET"])
@login_required
@limiter.limit("5 per minute")
def download_pdf():
    try:
        # Get all data from session
        whois_data = session.get('whois_data')
        email_validation = session.get('email_validation')
        website_title = session.get('website_title')
        ip_geolocation = session.get('ip_geolocation')
        shodan_scan = session.get('shodan_scan')
        wayback_urls = session.get('wayback_urls')

        if not all([whois_data, email_validation, website_title, ip_geolocation, shodan_scan]):
            flash("No scan data available. Please perform a scan first.")
            return redirect(url_for('index'))

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Title and Header
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, height - 50, "Recon X Intelligence Report")
        
        p.setFont("Helvetica", 10)
        p.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        p.drawString(50, height - 90, f"Generated by: {current_user.username}")
        p.line(50, height - 100, width - 50, height - 100)
        
        y_position = height - 130

        # Function to add section with page break check
        def add_section(title, data, y_pos):
            if y_pos < 100:
                p.showPage()
                y_pos = height - 50
            
            p.setFont("Helvetica-Bold", 12)
            p.drawString(50, y_pos, title)
            p.setFont("Helvetica", 10)
            y_pos -= 20
            
            if isinstance(data, (list, dict)):
                if isinstance(data, dict):
                    items = data.items()
                else:
                    items = enumerate(data)
                
                for key, value in items:
                    if y_pos < 100:
                        p.showPage()
                        y_pos = height - 50
                        p.setFont("Helvetica", 10)
                    
                    text = f"{key}: {value}" if isinstance(data, dict) else str(value)
                    p.drawString(70, y_pos, text[:100] + '...' if len(text) > 100 else text)
                    y_pos -= 15
            else:
                if y_pos < 100:
                    p.showPage()
                    y_pos = height - 50
                    p.setFont("Helvetica", 10)
                
                text = str(data)
                p.drawString(70, y_pos, text[:100] + '...' if len(text) > 100 else text)
                y_pos -= 15
            
            return y_pos - 20

        # Add all sections
        sections = [
            ("WHOIS Information", whois_data),
            ("Email Validation", email_validation),
            ("Website Title", website_title),
            ("IP Geolocation", ip_geolocation),
            ("Shodan Scan Results", shodan_scan),
            ("Historical URLs (Wayback Machine)", wayback_urls)
        ]

        for title, data in sections:
            if data:
                y_position = add_section(title, data, y_position)

        p.showPage()
        p.save()
        buffer.seek(0)
        
        return send_file(
            buffer,
            download_name='recon_x_report.pdf',
            as_attachment=True,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        flash(f"Error generating PDF: {str(e)}")
        return redirect(url_for('index'))

# Store results in session after scan
def store_results_in_session(whois_data, email_validation, website_title, ip_geolocation, shodan_scan, wayback_urls):
    """Store all scan results in session for PDF generation"""
    session['whois_data'] = whois_data
    session['email_validation'] = email_validation
    session['website_title'] = website_title
    session['ip_geolocation'] = ip_geolocation
    session['shodan_scan'] = shodan_scan
    session['wayback_urls'] = wayback_urls
    session.modified = True

if __name__ == "__main__":
    app.run(debug=True)
