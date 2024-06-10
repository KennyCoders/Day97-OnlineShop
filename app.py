import os
import time
import stripe
from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm



#Flask and DB set up
app = Flask(__name__)
app.config['SECRET_KEY'] = '123451' # Hosted locally, so yea.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # SQLite database stored locally
db = SQLAlchemy(app)


# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

#Stripe Set up (Checkout)
stripe.api_key = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'
YOUR_DOMAIN = 'http://localhost:5000'



#================ User Database==============#
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

#================ Product Database==============#
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)



#===================Functions==================#

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user email is already present in the database.
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("You've already signed up with that email, log in instead!")
            time.sleep(3)
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password. Please try again.")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    session.pop('cart', None)
    return redirect(url_for('index'))


@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)


@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product.html', product=product)



@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if not current_user.is_authenticated:
        flash('Please log in to add items to your cart.', 'info')
        return redirect(url_for('login'))

    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append(product_id)
    flash('Item added to cart!', 'success')
    return redirect(url_for('index'))


@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'cart' in session:
        session['cart'].remove(product_id)
        flash('Item removed from cart!', 'danger')
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty!', 'info')
        return render_template('cart.html', cart_items=[])

    cart_items = []
    total_price = 0
    for product_id in session['cart']:
        product = Product.query.get(product_id)
        if product:
            cart_items.append(product)
            total_price += product.price

    total_price = round(total_price, 2)

    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


#Check out session for Stripe
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty!', 'info')
        return redirect(url_for('cart'))

    # Constructing the line items for the checkout session
    line_items = []
    for product_id in session['cart']:
        product = Product.query.get(product_id)
        if product:
            line_items.append({
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': product.name,
                    },
                    'unit_amount': int(product.price * 100),
                },
                'quantity': 1,
            })

    # Creating the checkout session
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=line_items,
            payment_method_types=['card'],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success.html',
            cancel_url=YOUR_DOMAIN + '/cancel.html',
        )
    except Exception as e:
        flash(f'Error creating checkout session: {str(e)}', 'danger')
        return redirect(url_for('cart'))

    return redirect(checkout_session.url, code=303)

if __name__ == '__main__':
    app.run(debug=True)
