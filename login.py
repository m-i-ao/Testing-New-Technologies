from flask import Flask, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from main import app  # Убедись, что `app` импортируется из твоего основного файла
from main import User  # Замени `your_model_file` на имя файла, где у тебя объявлен User
from werkzeug.security import check_password_hash
from main import LoginForm  # Замени `your_forms_file` на имя файла с формами
from flask import Flask, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from main import User  # Замените на актуальный импорт вашей модели пользователя
from forms import LoginForm  # Убедись, что у тебя есть форма входа


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('admin_panel')) if user.is_admin else redirect(url_for('index'))
        else:
            flash('Ошибка входа. Проверьте логин и пароль.', 'danger')
    return render_template('login.html', form=form)
