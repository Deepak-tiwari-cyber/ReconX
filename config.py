import os
from dotenv import load_dotenv, find_dotenv


# Load environment variables from .env file
load_dotenv(find_dotenv())


# API Keys
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "default_shodan_key")

IPINFO_ACCESS_TOKEN = os.getenv("IPINFO_ACCESS_TOKEN", "default_ipinfo_token")


# Flask Configuration
class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
