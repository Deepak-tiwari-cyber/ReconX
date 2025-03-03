# Recon X - OSINT Intelligence Tool

A powerful web-based OSINT (Open Source Intelligence) tool that provides the following features:

## Features

- WHOIS Data Retrieval
- Email Validation
- Website Title Extraction
- IP Geolocation
- Shodan Scanning
- Historical URL Lookup (Wayback Machine)
- PDF Report Generation
- Multi-user Support
- Admin Panel

## Setup

1. Install required packages:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
SHODAN_API_KEY=your_shodan_api_key
IPINFO_ACCESS_TOKEN=your_ipinfo_token
SECRET_KEY=your_secret_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

3. Run the application:
```bash
python app.py
```

## Security Features

- User Authentication
- Rate Limiting
- API Key Validation
- Session Management

## API Endpoints

- `/`: Main scanning page
- `/login`: Login page
- `/register`: Registration page
- `/admin`: Admin panel
- `/download_pdf`: PDF report download

## Contributing

Please send pull requests to contribute to this project.
