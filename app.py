from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key'

# Initialize MongoDB Client
client = MongoClient(app.config['MONGO_URI'])
db = client.smart_door_lock

@app.route('/')
def index():
    if 'username' in session:
        user_data = db.user_data.find_one({"username": session['username']})
        if user_data:
            is_admin = user_data.get("is_admin", False)
            accessible_doors = user_data.get("access", [])  # Get user's accessible doors
            doors = list(db.doors.find({}))  # Fetch all doors
            return render_template('index.html', username=session['username'], doors=doors, is_admin=is_admin, accessible_doors=accessible_doors)

    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = db.user_data.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        return "Invalid credentials", 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        if db.user_data.find_one({"username": username}):
            return "User already exists", 400
        
        db.user_data.insert_one({"username": username, "password": hashed_password, "access": []})

        # Automatically make the first user an admin
        if db.user_data.count_documents({}) == 1:
            db.user_data.update_one({"username": username}, {"$set": {"is_admin": True}})

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/admin_panel')
def admin_panel():
    if 'username' in session:
        user = db.user_data.find_one({"username": session['username']})
        if user and user.get('is_admin'):
            users = list(db.user_data.find({}))
            return render_template('admin.html', users=users, doors=list(db.doors.find({})))
    return redirect(url_for('login'))

@app.route('/remove_user/<user_id>', methods=['POST'])  
def remove_user(user_id):
    user_to_delete = db.user_data.find_one({"_id": ObjectId(user_id)})
    if user_to_delete and user_to_delete['username'] != session['username']:
        db.user_data.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('admin_panel'))  

@app.route('/toggle_admin/<user_id>', methods=['POST'])
def toggle_admin(user_id):
    user = db.user_data.find_one({"_id": ObjectId(user_id)})
    if user:
        new_status = not user.get('is_admin', False)
        db.user_data.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_admin": new_status}})
    return redirect(url_for('admin_panel'))  

@app.route('/doors', methods=['GET', 'POST'])
def manage_doors():
    if request.method == 'POST':
        door_name = request.form['door_name']
        db.doors.insert_one({"name": door_name, "is_locked": False, "access": []})  # Default to unlocked
        return redirect(url_for('index'))

@app.route('/lock/<door_id>', methods=['POST'])
def lock_door(door_id):
    db.doors.update_one({"_id": ObjectId(door_id)}, {"$set": {"is_locked": True}})
    return redirect(url_for('index'))

@app.route('/unlock/<door_id>', methods=['POST'])
def unlock_door(door_id):
    db.doors.update_one({"_id": ObjectId(door_id)}, {"$set": {"is_locked": False}})
    return redirect(url_for('index'))

@app.route('/remove/<door_id>', methods=['POST'])
def remove_door(door_id):
    db.doors.delete_one({"_id": ObjectId(door_id)})
    return redirect(url_for('index'))

@app.route('/lock_all_doors', methods=['POST'])
def lock_all_doors():
    db.doors.update_many({}, {"$set": {"is_locked": True}})
    return redirect(url_for('index'))

@app.route('/modify_access/<user_id>', methods=['POST'])
def modify_access(user_id):
    access = request.form.getlist('door_access')  # Get selected doors from form
    db.user_data.update_one({"_id": ObjectId(user_id)}, {"$set": {"access": access}})
    return redirect(url_for('admin_panel'))

@app.route('/get_doors')
def get_doors():
    doors = list(db.doors.find({}))  # Fetch all doors
    return jsonify({"doors": doors})

@app.route('/get_user_access/<user_id>')
def get_user_access(user_id):
    user = db.user_data.find_one({"_id": ObjectId(user_id)})
    if user:
        return jsonify({
            "username": user['username'],
            "access": user.get('access', [])
        })
    return jsonify({"error": "User not found"}), 404


if __name__ == '__main__':
    app.run(debug=True)
