import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)

# Access Firestore
db = firestore.client()

# Unlock admin login
db.collection('settings').document('admin').set({
    'lock_admin_login': False
})

print("✅ Admin login has been unlocked.")
