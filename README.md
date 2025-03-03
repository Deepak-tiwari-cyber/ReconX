# OSINT Intelligence Tool

यह एक वेब-आधारित OSINT (Open Source Intelligence) टूल है जो निम्नलिखित सुविधाएं प्रदान करता है:

## सुविधाएं

- WHOIS डेटा रिट्रीवल
- ईमेल वैलिडेशन
- वेबसाइट टाइटल एक्सट्रैक्शन
- IP जियोलोकेशन
- Shodan स्कैनिंग
- PDF रिपोर्ट जनरेशन
- मल्टी-यूजर सपोर्ट
- एडमिन पैनल

## सेटअप

1. आवश्यक पैकेज इंस्टॉल करें:
```bash
pip install -r requirements.txt
```

2. एनवायरनमेंट वेरिएबल्स सेट करें:
```bash
SHODAN_API_KEY=your_shodan_api_key
IPINFO_ACCESS_TOKEN=your_ipinfo_token
SECRET_KEY=your_secret_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

3. एप्लिकेशन चलाएं:
```bash
python app.py
```

## सुरक्षा सुविधाएं

- यूजर ऑथेंटिकेशन
- रेट लिमिटिंग
- API की वैलिडेशन
- सेशन मैनेजमेंट

## API एंडपॉइंट्स

- `/`: मुख्य स्कैनिंग पेज
- `/login`: लॉगिन पेज
- `/register`: रजिस्ट्रेशन पेज
- `/admin`: एडमिन पैनल
- `/download_pdf`: PDF रिपोर्ट डाउनलोड

## योगदान

इस प्रोजेक्ट में योगदान करने के लिए कृपया पुल रिक्वेस्ट भेजें।

## लाइसेंस

MIT License 