class Config:
    DB_NAME = 'prod.db'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'admin123'
    SECRET_KEY = "AnirudhKabra"
    MODEL_PATH = 'ml-model/malware_model.pkl'
    SESSION_TIMEOUT = 30