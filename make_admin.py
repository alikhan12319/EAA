from app import db, User, app  # Импортируем app

# Входим в контекст приложения
with app.app_context():
    # Ищем пользователя
    user = User.query.filter_by(username='admin').first()

    if user:
        user.is_admin = True  # Назначаем админом
        db.session.commit()
        print(f"Пользователь {user.username} теперь админ!")
    else:
        print("Пользователь не найден!")
