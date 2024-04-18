import os

# Base directory calculation for consistent file paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration class."""
    DATABASE_PATH = os.path.join(BASE_DIR, 'user_data.db')
    IMAGE_SAVE_PATH = os.path.join(BASE_DIR, 'saved_images/')
    LOGGING_PATH = os.path.join(BASE_DIR, 'application.log')

class DevelopmentConfig(Config):
    """Development-specific configuration."""
    DEBUG = True

class ProductionConfig(Config):
    """Production-specific configuration."""
    DEBUG = False

# Using an environment variable to choose the configuration
current_config = DevelopmentConfig if os.getenv('ENV') == 'development' else ProductionConfig
