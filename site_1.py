from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask import Flask
from flask_login import LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request
app = Flask(__name__)

# Пример списка товаров
products = [
    {
        'id': 1,
        'name': 'Товар 1',
        'description': 'Описание товара 1',
        'image': 'images/product1.jpg',
        'category': 'Категория A'
    },
    {
        'id': 2,
        'name': 'Товар 2',
        'description': 'Описание товара 2',
        'image': 'images/product2.jpg',
        'category': 'Категория B'
    }
]

@app.route('/')
def index():
    # Если передан параметр для фильтрации по категории
    category = request.args.get('category')
    if category:
        filtered_products = [p for p in products if p['category'] == category]
    else:
        filtered_products = products
    return render_template('index.html', products=filtered_products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return render_template('product_detail.html', product=product)
    else:
        return "Товар не найден", 404

if __name__ == '__main__':
    # Для доступа из сети используем host='0.0.0.0'
    app.run(host='0.0.0.0', port=5000, debug=True)

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('admin')) if user.is_admin else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    categories = Category.query.all()
    return render_template('admin.html', categories=categories)

@app.route('/admin/category/add', methods=['POST'])
@login_required
def add_category():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    category_name = request.form.get('category_name')
    if category_name:
        new_category = Category(name=category_name)
        db.session.add(new_category)
        db.session.commit()
        flash('Category added successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/product/add', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    product_name = request.form.get('product_name')
    description = request.form.get('description')
    image_url = request.form.get('image_url')
    category_id = request.form.get('category_id')
    if product_name and description and category_id:
        new_product = Product(name=product_name, description=description, image_url=image_url, category_id=category_id)
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully!', 'success')
    return redirect(url_for('admin'))