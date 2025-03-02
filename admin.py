from main import db, User, app
from werkzeug.security import generate_password_hash

# Создаем контекст приложения перед работой с БД
with app.app_context():
    db.create_all()

    # Добавляем администратора, если его еще нет
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password=generate_password_hash("adminpass", method="pbkdf2:sha256"), is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("✅ Администратор создан: admin / adminpass")
    else:
        print("ℹ️ Администратор уже существует.")
