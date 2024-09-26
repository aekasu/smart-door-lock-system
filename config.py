import os

class Config:
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/smart_door_lock')
