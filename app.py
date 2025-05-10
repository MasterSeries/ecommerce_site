from flask import Flask, render_template, request, redirect, session, url_for, flash
import os
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
from flask import request
import requests
from flask import request, redirect, url_for, flash
from datetime import datetime




# -------------------- Firebase Setup --------------------
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# -------------------- Flask Setup --------------------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV') == 'production',
    SESSION_COOKIE_SAMESITE='Lax'
)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -------------------- Helper Functions --------------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def update_order_status(order_id, new_status):
    db = firestore.Client()
    order_ref = db.collection('orders').document(order_id)

    @firestore.transactional
    def update_in_transaction(transaction, order_ref):
        snapshot = order_ref.get(transaction=transaction)
        if snapshot.exists:
            transaction.update(order_ref, {'status': new_status})
        else:
            raise ValueError("Order not found")

    update_in_transaction(db.transaction(), order_ref)
def log_login(username):
    db.collection('login_logs').add({
        'username': username,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'ip_address': request.remote_addr
    })
def log_user_login(username, ip_address):
    location = get_location(ip_address)
    db.collection('login_logs').add({
        'username': username,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'ip_address': ip_address,
        'location': location
    })


def get_location(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        data = response.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except:
        return "Unknown Location"



def upload_image(image):
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)
        return filename
    return 'default.png'

def add_product_to_firebase(name, price, stock, image_filename):
    product_data = {
        'name': name,
        'price': price,
        'stock': stock,
        'image': image_filename
    }
    doc_ref = db.collection("products").add(product_data)
    return doc_ref[1].id

def get_all_products():
    return [{'id': p.id, **p.to_dict()} for p in db.collection('products').stream()]

def get_user_from_firebase(username):
    doc = db.collection('users').document(username).get()
    return doc.to_dict() if doc.exists else None

# In add_user_to_firebase
def add_user_to_firebase(username, password, role='user'):
    hashed_password = generate_password_hash(password)
    db.collection('users').document(username).set({'password': hashed_password, 'role': role})


def save_order_to_firebase(username, product_id, quantity):
    product = db.collection('products').document(product_id).get().to_dict()
    if not product:
        return
    order_data = {
        'username': username,
        'product_id': product_id,
        'product_name': product['name'],
        'image': product.get('image', ''),
        'price': product['price'],
        'quantity': quantity,
        'subtotal': product['price'] * quantity,
        'order_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'estimated_delivery': (datetime.utcnow() + timedelta(days=3)).strftime('%Y-%m-%d'),
        'status': 'Pending'
    }
    db.collection('orders').add(order_data)

def is_admin_locked():
    doc = db.collection('settings').document('admin').get()
    return doc.to_dict().get('lock_admin_login', False)

def lock_admin_login():
    db.collection('settings').document('admin').set({'lock_admin_login': True})

def unlock_admin_login():
    db.collection('settings').document('admin').set({'lock_admin_login': False})

# -------------------- Routes --------------------

@app.route('/')
def home():
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()  # Clears the session
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        ip_address = request.remote_addr

        if uname == 'azeem':
            if is_admin_locked():
                flash('Admin login is locked.')
                return redirect(url_for('login'))
            if pwd == 'azeem':
                session['username'] = 'azeem'
                session['role'] = 'admin'
                session.permanent = True  # Make the session permanent
                app.permanent_session_lifetime = timedelta(days=30)  # Set session expiration time
                log_user_login(uname, ip_address)
                return redirect('/admin')
            else:
                flash("Invalid admin credentials")
                return redirect('/login')

        user = get_user_from_firebase(uname)
        if user and check_password_hash(user['password'], pwd):
            session['username'] = uname
            session['role'] = user['role']
            session.permanent = True  # Make the session permanent
            app.permanent_session_lifetime = timedelta(days=30)  # Set session expiration time
            log_user_login(uname, ip_address)
            return redirect('/user')
        else:
            flash("Invalid credentials")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        if username == 'admin' or username == 'azeem':
            flash("You cannot use this username.")
            return redirect('/signup')

        add_user_to_firebase(
            username,
            request.form['password']
        )
        flash("User created successfully, please log in.")
        return redirect('/login')
    return render_template('signup.html')
@app.route('/admin/logs')
def admin_logs():
    if session.get('role') != 'admin':
        return redirect('/login')

    logs = [log.to_dict() for log in db.collection('login_logs').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()]
    return render_template('admin_logs.html', logs=logs)
@app.route('/admin/orders/clear', methods=['POST'])
def clear_all_orders():
    if session.get('role') != 'admin':
        return redirect('/login')
    for order in db.collection('orders').stream():
        order.reference.delete()
    flash("All orders have been cleared.")
    return redirect(url_for('admin_orders'))
@app.route('/admin/logs/export')
def export_logs():
    if session.get('role') != 'admin':
        return redirect('/login')

    import csv
    from flask import Response

    logs = [log.to_dict() for log in db.collection('login_logs').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()]

    def generate():
        yield 'Username,Timestamp,IP Address\n'
        for log in logs:
            yield f"{log['username']},{log['timestamp']},{log['ip_address']}\n"

    return Response(generate(), mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=login_logs.csv'
    })

@app.route('/admin')
@limiter.limit("10 per minute")
def admin_home():
    if session.get('role') == 'admin':
        return render_template('admin_home.html', products=get_all_products())
    return redirect('/login')

@app.route('/user')
def user_home():
    if session.get('role') == 'user':
        return render_template('user_home.html', products=get_all_products())
    return redirect('/login')

@app.route('/add_product', methods=['POST'])
def add_product():
    if session.get('role') != 'admin':
        return redirect('/login')

    image_filename = upload_image(request.files['image'])
    add_product_to_firebase(
        request.form['name'],
        float(request.form['price']),
        int(request.form['stock']),
        image_filename
    )
    flash("Product added successfully.")
    return redirect('/admin')

@app.route('/admin/products/<product_id>/edit', methods=['GET', 'POST'])
def edit_product_admin(product_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    product_ref = db.collection('products').document(product_id)

    if request.method == 'POST':
        image = request.files.get('image')
        data = {
            'name': request.form['name'],
            'price': float(request.form['price']),
            'stock': int(request.form['stock'])
        }
        if image and image.filename:
            data['image'] = upload_image(image)

        product_ref.update(data)
        flash("Product updated successfully.")
        return redirect('/admin')

    product = product_ref.get().to_dict()
    if not product:
        flash("Product not found.")
        return redirect('/admin')

    return render_template('edit_product.html', product=product, product_id=product_id)


@app.route('/order/<product_id>', methods=['GET', 'POST'])
def order(product_id):
    if session.get('role') != 'user':
        return redirect('/login')

    product_ref = db.collection('products').document(product_id)
    product = product_ref.get().to_dict()

    if product:
        if request.method == 'POST':
            # Get the quantity from the form
            quantity = int(request.form['quantity'])
            
            # Check if enough stock is available
            if product['stock'] >= quantity:
                # Save order to Firebase and update stock
                save_order_to_firebase(session['username'], product_id, quantity)
                product_ref.update({'stock': product['stock'] - quantity})
                flash("Order placed successfully.")
                return redirect('/user')
            else:
                flash("Not enough stock available!")
        
        # Render the product details page where the user can select a quantity
        return render_template('product_detail.html', product=product)
    else:
        flash("Product not found!")
        return redirect('/user')


@app.route('/checkout/<product_id>', methods=['GET', 'POST'])
def checkout(product_id):
    if session.get('role') != 'user':
        return redirect('/login')

    product_ref = db.collection('products').document(product_id)
    product_doc = product_ref.get()

    if product_doc.exists:
        product = product_doc.to_dict()
        if request.method == 'POST':
            quantity = int(request.form['quantity'])
            if product['stock'] >= quantity:
                save_order_to_firebase(session['username'], product_id, quantity)
                product_ref.update({'stock': product['stock'] - quantity})
                flash("Order placed successfully.")  # Optional: remove if not needed anymore
                return redirect(url_for('order_success', product_id=product_id))

            else:
                flash("Not enough stock!")
        return render_template('checkout.html', product=product)
    else:
        flash("Product not found!")
        return redirect('/user')

@app.route('/admin/products', methods=['GET', 'POST'])
def admin_products():
    if session.get('role') != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        image_filename = upload_image(request.files['image'])
        add_product_to_firebase(
            request.form['name'],
            float(request.form['price']),
            int(request.form['stock']),
            image_filename
        )
        flash("Product added successfully.")
        return redirect('/admin/products')

    return render_template('admin_products.html', products=get_all_products())

@app.route('/admin/orders')
def admin_orders():
    if session.get('role') != 'admin':
        return redirect('/login')

    orders = [{'id': o.id, **o.to_dict()} for o in db.collection('orders').stream()]
    return render_template('admin_orders.html', orders=orders)


@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if session.get('role') != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        user_to_remove = request.form.get('remove_user')
        if user_to_remove:
            db.collection('users').document(user_to_remove).delete()
            flash(f"User {user_to_remove} removed successfully.")

    users = [{'username': u.id, **u.to_dict()} for u in db.collection('users').stream()]
    return render_template('admin_users.html', users=users)


@app.route('/admin/lock', methods=['POST'])
def lock_admin():
    if session.get('role') != 'admin':
        return redirect('/login')

    action = request.form['action']
    if action == 'lock':
        lock_admin_login()
        flash("Admin login is now locked.")
    elif action == 'unlock':
        unlock_admin_login()
        flash("Admin login is now unlocked.")
    return redirect('/admin')

@app.route('/admin/product/<product_id>')
def view_product(product_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    product_ref = db.collection('products').document(product_id)
    product_doc = product_ref.get()

    if product_doc.exists:
        product = product_doc.to_dict()
        product['id'] = product_id
        return render_template('view_product.html', product=product)
    return "Product not found", 404

@app.route('/confirm_order/<product_id>', methods=['POST'])
def confirm_order(product_id):
    if session.get('role') != 'user':
        return redirect('/login')

    quantity = int(request.form['quantity'])
    product_ref = db.collection('products').document(product_id)
    product = product_ref.get().to_dict()

    if product and product['stock'] >= quantity:
        save_order_to_firebase(session['username'], product_id, quantity)
        product_ref.update({'stock': product['stock'] - quantity})
        flash("Order confirmed successfully!")
    else:
        flash("Not enough stock!")

    return redirect('/user')

@app.route('/order_success/<product_id>')
def order_success(product_id):
    product = db.collection('products').document(product_id).get().to_dict()
    return render_template('order_success.html', product=product)


@app.route('/admin/products/<product_id>/remove')
def remove_product_admin(product_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    db.collection('products').document(product_id).delete()
    flash("Product removed successfully.")
    return redirect('/admin')


@app.route('/admin/users/delete/<username>', methods=['POST'])
def delete_user(username):
    if session.get('role') != 'admin':
        return redirect('/login')

    db.collection('users').document(username).delete()
    flash(f"User '{username}' deleted.")
    return redirect(url_for('admin_users'))

@app.route('/admin/products/clear', methods=['POST'])
def clear_products():

    # Fetch and delete all product docs
    products_ref = db.collection('products')
    docs = products_ref.stream()
    for doc in docs:
        doc.reference.delete()

    flash("✅ All products have been deleted.", "success")
    return redirect(url_for('admin_products'))


@app.route('/admin/orders/<order_id>/update', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get('status')
    if not new_status:
        flash("Invalid status provided.", "danger")
        return redirect(url_for('admin_orders'))

    try:
        order_ref = db.collection('orders').document(order_id)
        order_ref.update({
            'status': new_status,
            'last_updated': datetime.utcnow()
        })
        flash(f"✅ Order #{order_id} status updated to '{new_status}'.", "success")
    except Exception as e:
        flash(f"❌ Failed to update order status: {str(e)}", "danger")

    return redirect(url_for('admin_orders'))


@app.route('/my-orders')
def my_orders():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session.get('username')
    orders_ref = db.collection('orders').where('username', '==', username)
    orders = [doc.to_dict() | {'id': doc.id} for doc in orders_ref.stream()]

    return render_template('user_orders.html', orders=orders)

@app.route('/track/<order_id>')
def track_order(order_id):
    return f"Tracking order: {order_id}"



@app.route('/reorder/<order_id>')
def reorder(order_id):
    username = session.get('username')
    if not username:
        flash('You must be logged in to reorder.', 'warning')
        return redirect(url_for('login'))

    try:
        # Get the original order
        order_doc = db.collection('orders').document(order_id).get()
        if not order_doc.exists:
            flash('Original order not found.', 'danger')
            return redirect(url_for('my_orders'))

        original_order = order_doc.to_dict()

        # Validate required fields
        required_fields = ['product_id', 'product_name', 'quantity', 'subtotal']
        if not all(field in original_order for field in required_fields):
            flash('Original order is missing required data.', 'danger')
            return redirect(url_for('my_orders'))

        # Create a new order based on the original
        new_order = {
            'username': username,
            'product_id': original_order['product_id'],
            'product_name': original_order['product_name'],
            'quantity': original_order['quantity'],
            'subtotal': original_order['subtotal'],
            'status': 'Pending',
            'order_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'estimated_delivery': (datetime.utcnow() + timedelta(days=3)).strftime('%Y-%m-%d')
        }

        db.collection('orders').add(new_order)
        flash('Reorder placed successfully.', 'success')
        return redirect(url_for('my_orders'))

    except Exception as e:
        flash(f"An error occurred while reordering: {str(e)}", 'danger')
        return redirect(url_for('my_orders'))


@app.route('/invoice/<order_id>')
def view_invoice(order_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    order_ref = db.collection('orders').document(order_id)
    order_doc = order_ref.get()

    if not order_doc.exists:
        flash("Order not found.", "danger")
        return redirect(url_for('my_orders'))

    order_data = order_doc.to_dict()
    order_data['id'] = order_id

    # Get user details
    user_data = {}
    user_id = order_data.get('user_id')
    if user_id:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()

    # Process product (single-product order support)
    items = []
    total_price = 0

    product_id = order_data.get('product_id')
    quantity = order_data.get('quantity', 1)

    if product_id:
        product_doc = db.collection('products').document(product_id).get()
        if product_doc.exists:
            product = product_doc.to_dict()
            price = product.get('price', 0)
            subtotal = price * quantity
            total_price = subtotal

            items.append({
                'product_name': product.get('name', 'Unnamed'),
                'quantity': quantity,
                'price': price,
                'subtotal': subtotal,
                'image_url': product.get('image_url')
            })
        else:
            # If product doc not found, fallback to existing order fields
            price = order_data.get('price', 0)
            subtotal = price * quantity
            total_price = subtotal

            items.append({
                'product_name': order_data.get('product_name', 'Unnamed'),
                'quantity': quantity,
                'price': price,
                'subtotal': subtotal,
                'image_url': order_data.get('image', '')
            })

    # Compose final order payload
    final_order = {
        'id': order_id,
        'timestamp': order_data.get('order_date', ''),
        'status': order_data.get('status', 'Pending'),
        'total_price': total_price,
        'items': items,
        'estimated_delivery': order_data.get('estimated_delivery', '')
    }

    # Include customer info
    final_order['customer_name'] = user_data.get('name', 'N/A')
    final_order['customer_email'] = user_data.get('email', 'N/A')
    final_order['customer_address'] = user_data.get('address', 'N/A')

    # Mark order as invoiced
    order_ref.update({
        'status': 'Invoiced'
    })

    # Debug info
    print("Order Items:", items)
    print(order_data)

    return render_template('invoice.html', order=final_order)


@app.route('/update_invoice/<order_id>', methods=['POST'])
def update_invoice(order_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Check if the user is allowed to update the invoice (admin or user)
    current_user = session['username']
    order_ref = db.collection('orders').document(order_id)
    order_doc = order_ref.get()

    if order_doc.exists:
        order_data = order_doc.to_dict()
        user_id = order_data.get('user_id')

        if current_user != user_id and not session.get('is_admin'):
            flash("You do not have permission to update this order.", "danger")
            return redirect(url_for('view_invoice', order_id=order_id))

    # Update the invoice
    order_ref.update({
        'status': 'Paid'
    })

    flash("Invoice updated to Paid", "success")
    return redirect(url_for('view_invoice', order_id=order_id))


@app.route('/select_shops/<order_id>', methods=['GET', 'POST'])
def select_shops(order_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        shop_names = request.form.get('shop_names')
        shops_list = [shop.strip() for shop in shop_names.split('\n') if shop.strip()]
        
        try:
            # Save shop list to the specific order document
            db.collection('orders').document(order_id).update({
                'shop_list': shops_list
            })
            flash('Shops updated successfully!', 'success')
        except Exception as e:
            print(f"Error saving shop list: {e}")
            flash('Failed to update shops.', 'danger')

        return redirect(url_for('orders'))

    return render_template('select_shops.html', order_id=order_id)




# -------------------- Main --------------------

if __name__ == '__main__':
    

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
