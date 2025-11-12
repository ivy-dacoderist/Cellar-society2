# ============================================
# IMPORTS
# ============================================
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify 
from werkzeug.security import generate_password_hash, check_password_hash
from auth_backend import authenticate_admin, authenticate_customer, register_customer
from user_backend import get_all_products, add_to_cart
from functools import wraps
from datetime import datetime
import sqlite3
import hashlib
import os
import json

# ============================================
# APP CONFIGURATION
# ============================================
app = Flask(__name__)
app.secret_key = 'cellar_society_secret_2025'



# ============================================
# TEMPLATE FILTERS
# ============================================
# Add these functions to app.py

def mask_email(email):
    """Mask email with asterisks except first 2 characters and domain"""
    if not email or '@' not in email:
        return email
    local_part, domain = email.split('@', 1)
    if len(local_part) <= 2:
        return '*' * len(local_part) + '@' + domain
    return local_part[:2] + '*' * (len(local_part) - 2) + '@' + domain

def mask_phone(phone):
    """Mask phone number with asterisks except last 2 digits"""
    if not phone:
        return phone
    phone_str = str(phone)
    if len(phone_str) <= 2:
        return '*' * len(phone_str)
    return '*' * (len(phone_str) - 2) + phone_str[-2:]

def mask_dob(dob):
    """Mask date of birth showing only year with asterisks for month/day"""
    if not dob:
        return dob
    try:
        # Handle different date formats
        if '-' in dob:
            year = dob.split('-')[0]
        elif '/' in dob:
            year = dob.split('/')[0]
        else:
            year = dob[-4:]  # Assume last 4 digits are year
        return '****/' + year
    except:
        return '****/****'

# Register the template filters
@app.template_filter('mask_email')
def mask_email_filter(email):
    return mask_email(email)

@app.template_filter('mask_phone')
def mask_phone_filter(phone):
    return mask_phone(phone)

@app.template_filter('mask_dob')
def mask_dob_filter(dob):
    return mask_dob(dob)

# ============================================
# DATABASE PATH (POINT TO PARENT FOLDER)
# ============================================
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cellar_society.db'))


# ============================================
# DATABASE SETUP
# ============================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Admins table
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Products
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        region TEXT NOT NULL,
        vintage INTEGER NOT NULL,
        price REAL NOT NULL,
        alcohol REAL NOT NULL,
        stock INTEGER NOT NULL,
        description TEXT,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Customers
    # In app.py - Update the customers table creation
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT NOT NULL,
       email TEXT UNIQUE NOT NULL,
       password TEXT NOT NULL,
       phone TEXT,
       date_of_birth TEXT,
       address TEXT,
       joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Cart table
    c.execute('''CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
    )''')

    # Orders
    # In your init_db() function, replace the orders table creation with:
    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        total_price REAL NOT NULL,
        status TEXT DEFAULT 'to_pay',
        seller_message TEXT,
        payment_method TEXT,
        address_id INTEGER,
        order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id),
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (address_id) REFERENCES user_addresses(id)
    )''')

    # User Addresses table
    c.execute('''CREATE TABLE IF NOT EXISTS user_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        label TEXT NOT NULL,
        full_name TEXT NOT NULL,
        phone_number TEXT NOT NULL,
        street_address TEXT NOT NULL,
        city TEXT NOT NULL,
        state TEXT NOT NULL,
        zip_code TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT 'Philippines',
        is_default BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id)
    )''')

    # Default admin
    c.execute("SELECT * FROM admins WHERE username='admin'")
    admin = c.fetchone()
    hashed_pw = hashlib.sha256('admin123'.encode()).hexdigest()

    if not admin:
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', hashed_pw))
    else:
        if admin[2] != hashed_pw:
            c.execute("UPDATE admins SET password=? WHERE username='admin'", (hashed_pw,))

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# CART COUNT HELPER FUNCTION
# ============================================
def get_cart_count(customer_id):
    conn = get_db_connection()
    count = conn.execute(
        'SELECT COUNT(DISTINCT product_id) FROM cart WHERE customer_id = ?',
        (customer_id,)
    ).fetchone()[0] or 0
    conn.close()
    return count

# ============================================
# HASH TABLE CACHE
# ============================================
class ProductHashTable:
    def __init__(self):
        self.table = {}

    def insert(self, product_id, product_data):
        self.table[product_id] = product_data

    def get(self, product_id):
        return self.table.get(product_id, None)

    def delete(self, product_id):
        if product_id in self.table:
            del self.table[product_id]
            return True
        return False

    def get_all(self):
        return list(self.table.values())

product_cache = ProductHashTable()

def load_products_to_cache():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    conn.close()

    product_cache.table.clear()
    for p in products:
        product_cache.insert(p[0], {
            'id': p[0],
            'name': p[1],
            'type': p[2],
            'region': p[3],
            'vintage': p[4],
            'price': p[5],
            'alcohol': p[6],
            'stock': p[7],
            'description': p[8],
            'image_url': p[9]
        })

# ============================================
# DECORATORS
# ============================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in as admin.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def customer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'customer_id' not in session:
            flash('Please log in as customer.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ============================================
# AUTH ROUTES
# ============================================
@app.route('/')
def index():
    if 'admin_id' in session:
        return redirect(url_for('dashboard'))
    elif 'customer_id' in session:
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']

        admin = authenticate_admin(username_or_email, password)
        if admin:
            session.clear()
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            flash(f"Welcome back, {admin['username']}!", 'success')
            return redirect(url_for('dashboard'))

        customer = authenticate_customer(username_or_email, password)
        if customer:
            session.clear()
            session['customer_id'] = customer['id']
            session['customer_name'] = customer['name']
            flash(f"Welcome, {customer['name']}!", 'success')
            return redirect(url_for('user_dashboard'))

        flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        phone = request.form.get('phone', '').strip() or None
        date_of_birth = request.form.get('date_of_birth', '').strip() or None

        if register_customer(name, email, password, confirm, phone, date_of_birth):
            return redirect(url_for('login'))
        else:
            return render_template('user/register.html')

    return render_template('user/register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# ============================================
# ADMIN ROUTES
# ============================================
@app.route('/dashboard')
@admin_required
def dashboard():
    conn = get_db_connection()
    total_products = conn.execute('SELECT COUNT(*) AS c FROM products').fetchone()['c']
    total_customers = conn.execute('SELECT COUNT(*) AS c FROM customers').fetchone()['c']
    total_orders = conn.execute('SELECT COUNT(*) AS c FROM orders').fetchone()['c']
    pending_orders = conn.execute('SELECT COUNT(*) AS c FROM orders WHERE status="Pending"').fetchone()['c']
    recent_orders = conn.execute('''
        SELECT o.id, c.name AS customer_name, p.name AS product_name,
               o.quantity, o.total_price, o.status, o.order_date
        FROM orders o
        JOIN customers c ON o.customer_id = c.id
        JOIN products p ON o.product_id = p.id
        ORDER BY o.order_date DESC
        LIMIT 5
    ''').fetchall()
    conn.close()

    return render_template('admin/dashboard.html',
                           stats={
                               'total_products': total_products,
                               'total_customers': total_customers,
                               'total_orders': total_orders,
                               'pending_orders': pending_orders
                           },
                           recent_orders=recent_orders)

@app.route('/products')
@admin_required
def products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('admin/products.html', products=products)

@app.route('/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        data = (
            request.form['name'],
            request.form['type'],
            request.form['region'],
            int(request.form['vintage']),
            float(request.form['price']),
            float(request.form['alcohol']),
            int(request.form['stock']),
            request.form.get('description', ''),
            request.form.get('image_url', '')
        )
        conn = get_db_connection()
        conn.execute('''INSERT INTO products 
                        (name, type, region, vintage, price, alcohol, stock, description, image_url)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
        conn.commit()
        conn.close()
        flash('Product added successfully!', 'success')
        return redirect(url_for('products'))
    return render_template('admin/add_product.html')

# ✅ FIXED: Edit Product Route
@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('products'))

    if request.method == 'POST':
        data = (
            request.form['name'],
            request.form['type'],
            request.form['region'],
            int(request.form['vintage']),
            float(request.form['price']),
            float(request.form['alcohol']),
            int(request.form['stock']),
            request.form.get('description', ''),
            request.form.get('image_url', ''),
            product_id
        )
        conn.execute('''UPDATE products 
                        SET name=?, type=?, region=?, vintage=?, price=?, alcohol=?, stock=?, description=?, image_url=?
                        WHERE id=?''', data)
        conn.commit()
        conn.close()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('products'))

    conn.close()
    return render_template('admin/edit_product.html', product=product)

@app.route('/customers')
@admin_required
def customers():
    search = request.args.get('search', '')
    conn = get_db_connection()
    query = 'SELECT * FROM customers WHERE 1=1'
    params = []
    if search:
        query += ' AND (name LIKE ? OR email LIKE ?)'
        params += [f'%{search}%', f'%{search}%']
    customers = conn.execute(query + ' ORDER BY joined_at DESC', params).fetchall()
    conn.close()
    return render_template('admin/customers.html', customers=customers, search=search)

# ✅ FIXED: Delete Product Route
@app.route('/products/delete/<int:product_id>', methods=['POST', 'GET'])
@admin_required
def delete_product(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        conn.close()
        return redirect(url_for('products'))

    conn.execute('DELETE FROM products WHERE id=?', (product_id,))
    conn.commit()
    conn.close()

    flash(f'Product "{product["name"]}" deleted successfully!', 'success')
    return redirect(url_for('products'))

# ✅ FIXED: Customer Detail Route
@app.route('/customers/<int:customer_id>')
@admin_required
def customer_detail(customer_id):
    conn = get_db_connection()
    customer = conn.execute('SELECT * FROM customers WHERE id=?', (customer_id,)).fetchone()
    orders = conn.execute('''
        SELECT o.*, p.name AS product_name
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.customer_id=?
    ''', (customer_id,)).fetchall()
    conn.close()
    if not customer:
        flash('Customer not found.', 'error')
        return redirect(url_for('customers'))
    return render_template('admin/customer_detail.html', customer=customer, orders=orders)

@app.route('/orders')
@admin_required
def orders():
    status_filter = request.args.get('status', '')
    conn = get_db_connection()
    query = '''
        SELECT o.*, c.name AS customer_name, p.name AS product_name
        FROM orders o
        JOIN customers c ON o.customer_id = c.id
        JOIN products p ON o.product_id = p.id
        WHERE 1=1
    '''
    params = []
    if status_filter:
        query += ' AND o.status=?'
        params.append(status_filter)
    orders = conn.execute(query + ' ORDER BY o.order_date DESC', params).fetchall()
    conn.close()
    return render_template('admin/orders.html', orders=orders, status_filter=status_filter)

# ============================================
# USER ROUTES
# ============================================
@app.route('/user/dashboard')
@customer_required
def user_dashboard():
    customer_id = session['customer_id']
    cart_count = get_cart_count(customer_id)
    products = get_all_products()  # fetch all products
    return render_template(
        'user/dashboard.html',
        customer_name=session.get('customer_name'),
        products=products,  # pass products to the template
        cart_count=cart_count
    )

@app.route('/user/orders')
@customer_required
def user_orders():
    """Display user's order history"""
    customer_id = session['customer_id']
    cart_count = get_cart_count(customer_id)
    conn = get_db_connection()
    
    try:
        # Get all orders for the customer with product details
        orders = conn.execute('''
            SELECT 
                o.id,
                o.order_date,
                o.quantity,
                o.total_price,
                o.status,
                o.seller_message,
                o.payment_method,
                p.name,
                p.type,
                p.image_url,
                p.price as unit_price,
                ua.full_name,
                ua.street_address,
                ua.city,
                ua.state,
                ua.zip_code,
                ua.country,
                ua.phone_number
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN user_addresses ua ON o.address_id = ua.id
            WHERE o.customer_id = ?
            ORDER BY o.order_date DESC
        ''', (customer_id,)).fetchall()
        
        # Group orders by order ID to handle multiple items per order
        orders_dict = {}
        for order in orders:
            order_data = dict(order)
            order_id = order_data['id']
            
            if order_id not in orders_dict:
                orders_dict[order_id] = {
                    'id': order_id,
                    'order_date': order_data['order_date'],
                    'total_amount': 0,
                    'status': order_data['status'],
                    'seller_message': order_data['seller_message'],
                    'payment_method': order_data['payment_method'],
                    'shipping_address': {
                        'full_name': order_data['full_name'],
                        'street_address': order_data['street_address'],
                        'city': order_data['city'],
                        'state': order_data['state'],
                        'zip_code': order_data['zip_code'],
                        'country': order_data['country'],
                        'phone_number': order_data['phone_number']
                    },
                    'items': []
                }
            
            # Add item to order
            orders_dict[order_id]['items'].append({
                'name': order_data['name'],
                'type': order_data['type'],
                'price': float(order_data['unit_price']),
                'quantity': order_data['quantity'],
                'image_url': order_data['image_url']
            })
            
            # Accumulate total amount
            orders_dict[order_id]['total_amount'] += float(order_data['total_price'])
        
        orders_list = list(orders_dict.values())
        
        return render_template('user/orders.html',
                             orders=orders_list,
                             cart_count=cart_count)
        
    except Exception as e:
        print(f"Error loading orders: {str(e)}")
        flash('Error loading orders.', 'error')
        return redirect(url_for('user_dashboard'))
    finally:
        conn.close()

# Add to Cart route
@app.route('/user/add_to_cart/<int:product_id>', methods=['POST'])
@customer_required
def add_to_cart_route(product_id):
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("You must be logged in to add items to your cart.", "error")
        return redirect(url_for('login'))

    add_to_cart(customer_id, product_id)
    flash("Product added to your cart!", "success")
    return redirect(url_for('user_dashboard'))

# Buy Now route (redirects to checkout later)
@app.route('/user/buy_now/<int:product_id>', methods=['POST'])
@customer_required
def buy_now_route(product_id):
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("You must be logged in to buy items.", "error")
        return redirect(url_for('login'))

    # For now, just add to cart then redirect (can later go to checkout)
    add_to_cart(customer_id, product_id)
    flash("Product added! Proceed to checkout.", "info")
    return redirect(url_for('user_dashboard'))

@app.route('/user/profile')
@customer_required
def user_profile():
    customer_id = session['customer_id']
    cart_count = get_cart_count(customer_id)
    conn = get_db_connection()
    
    # Get user info
    user = conn.execute('SELECT * FROM customers WHERE id=?', (customer_id,)).fetchone()
    
    # Get user addresses
    addresses = conn.execute('''
        SELECT * FROM user_addresses 
        WHERE customer_id = ? 
        ORDER BY is_default DESC, created_at DESC
    ''', (customer_id,)).fetchall()
    
    conn.close()
    
    # Pre-process the data for masking (temporary solution)
    user_dict = dict(user)
    user_dict['masked_email'] = mask_email(user['email']) if user['email'] else 'Not provided'
    user_dict['masked_phone'] = mask_phone(user['phone']) if user['phone'] else 'Not provided'
    user_dict['masked_dob'] = mask_dob(user['date_of_birth']) if user['date_of_birth'] else 'Not provided'
    
    # Convert addresses to list of dicts
    addresses_list = []
    for addr in addresses:
        addresses_list.append(dict(addr))
    
    return render_template('user/profile.html', user=user_dict, addresses=addresses_list, cart_count=cart_count)


@app.route('/user/update_profile', methods=['POST'])
@customer_required
def update_profile():
    """Update user profile information"""
    customer_id = session['customer_id']
    data = request.get_json()
    field = data.get('field')
    value = data.get('value')
    
    if not field or not value:
        return jsonify({'success': False, 'message': 'Invalid data'})
    
    allowed_fields = ['name', 'email', 'phone', 'date_of_birth']
    if field not in allowed_fields:
        return jsonify({'success': False, 'message': 'Invalid field'})
    
    conn = get_db_connection()
    try:
        # Check if email already exists (if updating email)
        if field == 'email':
            existing = conn.execute(
                'SELECT id FROM customers WHERE email = ? AND id != ?',
                (value, customer_id)
            ).fetchone()
            if existing:
                return jsonify({'success': False, 'message': 'Email already exists'})
        
        conn.execute(
            f'UPDATE customers SET {field} = ? WHERE id = ?',
            (value, customer_id)
        )
        conn.commit()
        
        # Update session if name is changed
        if field == 'name':
            session['customer_name'] = value
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/change_password', methods=['POST'])
@customer_required
def change_password():
    """Change user password"""
    customer_id = session['customer_id']
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'})
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
    
    conn = get_db_connection()
    try:
        # Get current user
        user = conn.execute(
            'SELECT * FROM customers WHERE id = ?',
            (customer_id,)
        ).fetchone()
        
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update password
        hashed_new_password = generate_password_hash(new_password)
        conn.execute(
            'UPDATE customers SET password = ? WHERE id = ?',
            (hashed_new_password, customer_id)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/delete_account', methods=['POST'])
@customer_required
def delete_account():
    """Delete user account after password verification"""
    customer_id = session['customer_id']
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'success': False, 'message': 'Password is required'})
    
    conn = get_db_connection()
    try:
        # Get current user
        user = conn.execute(
            'SELECT * FROM customers WHERE id = ?',
            (customer_id,)
        ).fetchone()
        
        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'message': 'Incorrect password'})
        
        # Check for pending orders
        pending_orders = conn.execute(
            'SELECT COUNT(*) FROM orders WHERE customer_id = ? AND status IN ("Pending", "Processing")',
            (customer_id,)
        ).fetchone()[0]
        
        if pending_orders > 0:
            return jsonify({'success': False, 'message': 'Cannot delete account with pending orders'})
        
        # Delete user data (in reverse order to respect foreign key constraints)
        conn.execute('DELETE FROM cart WHERE customer_id = ?', (customer_id,))
        conn.execute('DELETE FROM orders WHERE customer_id = ?', (customer_id,))
        conn.execute('DELETE FROM customers WHERE id = ?', (customer_id,))
        
        conn.commit()
        
        # Clear session
        session.clear()
        
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/cart')
@customer_required
def user_cart():
    """Display user's shopping cart"""
    customer_id = session['customer_id']
    cart_count = get_cart_count(customer_id)
    conn = get_db_connection()
    
    # Get cart items with product details
    cart_items = conn.execute('''
        SELECT c.*, p.name, p.type, p.price, p.stock, p.image_url
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.customer_id = ?
        ORDER BY c.created_at DESC
    ''', (customer_id,)).fetchall()
    
    # Calculate totals
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    shipping = 100.00  # Fixed shipping cost for demo
    total = subtotal + shipping
    
    conn.close()
    
    return render_template('user/cart.html', 
                         cart_items=cart_items,
                         subtotal=subtotal,
                         shipping=shipping,
                         total=total,
                         cart_count=cart_count)

@app.route('/user/update_cart_quantity', methods=['POST'])
@customer_required
def update_cart_quantity():
    """Update quantity of an item in the cart"""
    customer_id = session['customer_id']
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity')
    
    if not product_id or not quantity:
        return jsonify({'success': False, 'message': 'Invalid data'})
    
    conn = get_db_connection()
    try:
        # Check if product exists and has sufficient stock
        product = conn.execute(
            'SELECT stock FROM products WHERE id = ?',
            (product_id,)
        ).fetchone()
        
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        if quantity > product['stock']:
            return jsonify({'success': False, 'message': 'Not enough stock available'})
        
        # Update cart quantity
        conn.execute(
            'UPDATE cart SET quantity = ? WHERE customer_id = ? AND product_id = ?',
            (quantity, customer_id, product_id)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Quantity updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/remove_from_cart/<int:product_id>', methods=['DELETE'])
@customer_required
def remove_from_cart(product_id):
    """Remove an item from the cart"""
    customer_id = session['customer_id']
    conn = get_db_connection()
    try:
        conn.execute(
            'DELETE FROM cart WHERE customer_id = ? AND product_id = ?',
            (customer_id, product_id)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Item removed from cart'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/clear_cart', methods=['DELETE'])
@customer_required
def clear_cart():
    """Clear all items from the cart"""
    customer_id = session['customer_id']
    conn = get_db_connection()
    try:
        conn.execute(
            'DELETE FROM cart WHERE customer_id = ?',
            (customer_id,)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Cart cleared successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

# Address Management Routes
@app.route('/user/addresses')
@customer_required
def get_user_addresses():
    """Get all addresses for the current user"""
    customer_id = session['customer_id']
    conn = get_db_connection()
    addresses = conn.execute('''
        SELECT * FROM user_addresses 
        WHERE customer_id = ? 
        ORDER BY is_default DESC, created_at DESC
    ''', (customer_id,)).fetchall()
    conn.close()
    
    addresses_list = []
    for addr in addresses:
        addresses_list.append(dict(addr))
    
    return jsonify({'success': True, 'addresses': addresses_list})

@app.route('/user/addresses/add', methods=['POST'])
@customer_required
def add_user_address():
    """Add a new address for the current user"""
    customer_id = session['customer_id']
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['label', 'full_name', 'phone_number', 'street_address', 'city', 'state', 'zip_code', 'country']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'{field.replace("_", " ").title()} is required'})
    
    conn = get_db_connection()
    try:
        # If this is set as default, remove default from other addresses
        if data.get('is_default'):
            conn.execute(
                'UPDATE user_addresses SET is_default = 0 WHERE customer_id = ?',
                (customer_id,)
            )
        
        # Insert new address
        conn.execute('''
            INSERT INTO user_addresses 
            (customer_id, label, full_name, phone_number, street_address, city, state, zip_code, country, is_default)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            customer_id,
            data['label'],
            data['full_name'],
            data['phone_number'],
            data['street_address'],
            data['city'],
            data['state'],
            data['zip_code'],
            data['country'],
            1 if data.get('is_default') else 0
        ))
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Address added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/addresses/<int:address_id>/set_default', methods=['POST'])
@customer_required
def set_default_address(address_id):
    """Set an address as default"""
    customer_id = session['customer_id']
    conn = get_db_connection()
    try:
        # Remove default from all addresses
        conn.execute(
            'UPDATE user_addresses SET is_default = 0 WHERE customer_id = ?',
            (customer_id,)
        )
        
        # Set the selected address as default
        conn.execute(
            'UPDATE user_addresses SET is_default = 1 WHERE id = ? AND customer_id = ?',
            (address_id, customer_id)
        )
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Default address updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/user/addresses/<int:address_id>/delete', methods=['DELETE'])
@customer_required
def delete_user_address(address_id):
    """Delete a user address"""
    customer_id = session['customer_id']
    conn = get_db_connection()
    try:
        # Check if address exists and belongs to user
        address = conn.execute(
            'SELECT * FROM user_addresses WHERE id = ? AND customer_id = ?',
            (address_id, customer_id)
        ).fetchone()
        
        if not address:
            return jsonify({'success': False, 'message': 'Address not found'})
        
        # Check if it's the default address
        if address['is_default']:
            return jsonify({'success': False, 'message': 'Cannot delete default address'})
        
        # Delete the address
        conn.execute(
            'DELETE FROM user_addresses WHERE id = ? AND customer_id = ?',
            (address_id, customer_id)
        )
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Address deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

# ============================================
# USER ROUTES - CHECKOUT
# ============================================
@app.route('/user/checkout', methods=['GET', 'POST'])
@customer_required
def checkout_page():
    """Checkout page for placing orders"""
    customer_id = session['customer_id']
    print(f"DEBUG: checkout_page called - method: {request.method}")
    
    if request.method == 'POST':
        print(f"DEBUG: POST data: {request.form}")
        # Handle both cart checkout and buy now
        if 'selected_items' in request.form:
            # Coming from cart with selected items
            try:
                selected_items = json.loads(request.form['selected_items'])
                print(f"DEBUG: Cart checkout with items: {selected_items}")
                return render_checkout_page(customer_id, selected_items)
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON decode error: {e}")
                flash('Invalid cart selection.', 'error')
                return redirect(url_for('user_cart'))
        elif 'buy_now_product' in request.form:
            # Coming from buy now
            try:
                product_id = int(request.form['buy_now_product'])
                print(f"DEBUG: Buy now with product: {product_id}")
                return render_checkout_page(customer_id, [product_id], buy_now=True)
            except (ValueError, TypeError) as e:
                print(f"DEBUG: Buy now error: {e}")
                flash('Invalid product selection.', 'error')
                return redirect(url_for('user_dashboard'))
        else:
            print("DEBUG: No valid form data found")
    
    # If GET request or invalid POST, redirect to appropriate page
    print("DEBUG: Redirecting to dashboard - no valid POST data or GET request")
    flash('Please select items to checkout.', 'error')
    return redirect(url_for('user_dashboard'))

def render_checkout_page(customer_id, product_ids, buy_now=False):
    """Render checkout page with order items"""
    print(f"DEBUG: render_checkout_page called - customer_id: {customer_id}, product_ids: {product_ids}, buy_now: {buy_now}")
    
    conn = get_db_connection()
    
    try:
        # Get user addresses - convert to dicts
        addresses = conn.execute(
            'SELECT * FROM user_addresses WHERE customer_id = ? ORDER BY is_default DESC',
            (customer_id,)
        ).fetchall()
        addresses_dicts = [dict(address) for address in addresses]
        print(f"DEBUG: Found {len(addresses_dicts)} addresses")
        
        # Get order items
        order_items = []
        subtotal = 0
        
        if buy_now:
            # Single product buy now
            product = conn.execute(
                'SELECT * FROM products WHERE id = ?', (product_ids[0],)
            ).fetchone()
            if product:
                product_dict = dict(product)
                order_items.append({
                    'product_id': product_dict['id'],
                    'name': product_dict['name'],
                    'type': product_dict['type'],
                    'price': float(product_dict['price']),
                    'quantity': 1,
                    'stock': product_dict['stock'],  # Add stock information
                    'image_url': product_dict['image_url']
                })
                subtotal = float(product_dict['price'])
                print(f"DEBUG: Buy now product: {product_dict['name']}")
            else:
                print("DEBUG: Product not found")
                flash('Product not found.', 'error')
                return redirect(url_for('user_dashboard'))
        else:
            # Multiple products from cart
            if not product_ids:
                print("DEBUG: No product IDs provided")
                flash('No items selected.', 'error')
                return redirect(url_for('user_cart'))
                
            placeholders = ','.join('?' * len(product_ids))
            cart_items = conn.execute(f'''
                SELECT c.*, p.name, p.type, p.price, p.stock, p.image_url
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.customer_id = ? AND c.product_id IN ({placeholders})
            ''', [customer_id] + product_ids).fetchall()
            
            print(f"DEBUG: Found {len(cart_items)} cart items")
            
            for item in cart_items:
                item_dict = dict(item)
                order_items.append({
                    'product_id': item_dict['product_id'],
                    'name': item_dict['name'],
                    'type': item_dict['type'],
                    'price': float(item_dict['price']),
                    'quantity': item_dict['quantity'],
                    'stock': item_dict['stock'],  # Add stock information
                    'image_url': item_dict['image_url']
                })
                subtotal += float(item_dict['price']) * item_dict['quantity']
        
        if not order_items:
            print("DEBUG: No order items to checkout")
            flash('No valid items to checkout.', 'error')
            return redirect(url_for('user_dashboard'))
        
        print(f"DEBUG: Rendering checkout with {len(order_items)} items, subtotal: {subtotal}")
        
        # Prepare order data for form submission - ensure it's JSON serializable
        order_data = {
            'items': order_items,
            'buy_now': buy_now
        }
        
        return render_template('user/checkout.html',
                             addresses=addresses_dicts,  # Use the converted dicts
                             order_items=order_items,
                             subtotal=subtotal,
                             order_data=order_data,
                             cart_count=get_cart_count(customer_id))
    
    except Exception as e:
        print(f"DEBUG: Exception in render_checkout_page: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        flash(f'Error loading checkout page: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))
    finally:
        conn.close()

@app.route('/user/place_order', methods=['POST'])
@customer_required
def place_order():
    """Place the final order"""
    customer_id = session['customer_id']
    print(f"DEBUG: place_order called - customer_id: {customer_id}")
    
    try:
        address_id = request.form['address_id']
        payment_method = request.form['payment_method']
        seller_message = request.form.get('seller_message', '')
        order_data = json.loads(request.form['order_data'])
        
        print(f"DEBUG: Received data - address_id: {address_id}, payment_method: {payment_method}")
        print(f"DEBUG: Order data items: {len(order_data['items'])}")
        
        conn = get_db_connection()
        
        # Verify address belongs to user
        address = conn.execute(
            'SELECT * FROM user_addresses WHERE id = ? AND customer_id = ?',
            (address_id, customer_id)
        ).fetchone()
        
        if not address:
            print("DEBUG: Invalid shipping address")
            flash('Invalid shipping address.', 'error')
            return redirect(url_for('user_dashboard'))
        
        # Create orders for each item
        for item in order_data['items']:
            print(f"DEBUG: Processing item - product_id: {item['product_id']}, quantity: {item['quantity']}")
            
            # Verify product exists and has sufficient stock
            product = conn.execute(
                'SELECT * FROM products WHERE id = ?',
                (item['product_id'],)
            ).fetchone()
            
            if not product:
                print(f"DEBUG: Product not found: {item['product_id']}")
                flash(f"Product {item.get('name', 'Unknown')} not found.", 'error')
                return redirect(url_for('user_dashboard'))
            
            print(f"DEBUG: Product stock: {product['stock']}, requested quantity: {item['quantity']}")
            if product['stock'] < item['quantity']:
                print(f"DEBUG: Insufficient stock for product {item['product_id']}")
                flash(f"Not enough stock for {item.get('name', 'Unknown')}.", 'error')
                return redirect(url_for('user_dashboard'))
            
            # Insert order with address_id and payment_method
            print(f"DEBUG: Inserting order into database")
            conn.execute('''
                INSERT INTO orders (customer_id, product_id, quantity, total_price, status, 
                                  seller_message, payment_method, address_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                customer_id,
                item['product_id'],
                item['quantity'],
                item['price'] * item['quantity'],
                'to_pay',  # Initial status
                seller_message,
                payment_method,
                address_id
            ))
            
            # Update product stock
            conn.execute(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                (item['quantity'], item['product_id'])
            )
            
            # Remove from cart if it was in cart
            if not order_data.get('buy_now'):
                conn.execute(
                    'DELETE FROM cart WHERE customer_id = ? AND product_id = ?',
                    (customer_id, item['product_id'])
                )
        
        conn.commit()
        print("DEBUG: Order successfully placed, redirecting to user_orders")
        flash('Order placed successfully! You can view it in My Orders.', 'success')
        return redirect(url_for('user_orders'))
        
    except Exception as e:
        print(f"DEBUG: Exception in place_order: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        flash(f'Error placing order: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))
    

# ============================================
# RUN APP
# ============================================
if __name__ == '__main__':
    init_db()
    load_products_to_cache()
    print("=" * 60)
    print(" Cellar Society Admin & User Panel Starting...")
    print("=" * 60)
    print(" Access at: http://localhost:5000")
    print(" Default Admin Login: admin / admin123")
    print("=" * 60)
    app.run(debug=True, port=5000)