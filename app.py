import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
from flask import session
from flask_login import UserMixin
import base64
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

app = Flask(__name__)
app.secret_key = 'ваш_секретный_ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moysklad.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройка логирования
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    remember_credentials = db.Column(db.Boolean, default=False)
    tokens = db.relationship('Token', backref='user', lazy=True)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

# Создаем таблицы при запуске
with app.app_context():
    db.create_all()

TOKEN = "02bf2b522f9bb7671245b1c825e9d669a7cd581a"

headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}"
}

MOYSKLAD_API_URL = 'https://online.moysklad.ru/api/remap/1.2'
auth = HTTPBasicAuth(os.getenv('MOYSKLAD_LOGIN'), os.getenv('MOYSKLAD_PASSWORD'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/supplies')
def supplies_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('supplies.html')

@app.route('/supplies/new')
def new_supply_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('supply_new.html')

@app.route('/supplies/<string:supply_id>')
def supply_detail_page(supply_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('supply_detail.html')

@app.route('/api/supplies/<string:supply_id>', methods=['GET', 'PUT'])
def supply_details(supply_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Не авторизован'}), 401

    user = User.query.get(session['user_id'])
    token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

    if request.method == 'GET':
        try:
            response = requests.get(
                f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}',
                headers={
                    'Authorization': f'Bearer {token.access_token}',
                    'Accept-Encoding': 'gzip'
                }
            )
            
            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({'error': 'Ошибка получения данных приёмки'}), response.status_code

        except Exception as e:
            app.logger.error(f'Ошибка при получении данных приёмки: {str(e)}')
            return jsonify({'error': str(e)}), 500

    elif request.method == 'PUT':
        try:
            data = request.json
            response = requests.put(
                f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}',
                headers={
                    'Authorization': f'Bearer {token.access_token}',
                    'Accept-Encoding': 'gzip',
                    'Content-Type': 'application/json'
                },
                json=data
            )
            
            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({'error': 'Ошибка обновления приёмки'}), response.status_code

        except Exception as e:
            app.logger.error(f'Ошибка при обновлении приёмки: {str(e)}')
            return jsonify({'error': str(e)}), 500

@app.route('/receipts')
def get_receipts():
    response = requests.get(f'{MOYSKLAD_API_URL}/entity/supply', auth=auth)
    if response.status_code == 200:
        supplies = response.json().get('rows', [])
        return render_template('receipts.html', supplies=supplies)
    else:
        flash('Ошибка при получении списка приёмок.')
        return redirect(url_for('index'))

@app.route('/receipt/<receipt_id>')
def get_receipt(receipt_id):
    response = requests.get(f'{MOYSKLAD_API_URL}/entity/supply/{receipt_id}', auth=auth)
    if response.status_code == 200:
        receipt = response.json()
        return render_template('receipt_detail.html', receipt=receipt)
    else:
        flash('Ошибка при получении деталей приёмки.')
        return redirect(url_for('get_receipts'))

@app.route('/receipt/<receipt_id>/edit', methods=['GET', 'POST'])
def edit_receipt(receipt_id):
    if request.method == 'POST':
        updated_data = {
            "description": request.form.get('description'),
            # Добавьте другие поля для обновления по мере необходимости
        }
        response = requests.put(f'{MOYSKLAD_API_URL}/entity/supply/{receipt_id}', json=updated_data, auth=auth)
        if response.status_code == 200:
            flash('Приёмка успешно обновлена.')
            return redirect(url_for('get_receipt', receipt_id=receipt_id))
        else:
            flash('Ошибка при обновлении приёмки.')
            return redirect(url_for('edit_receipt', receipt_id=receipt_id))
    else:
        response = requests.get(f'{MOYSKLAD_API_URL}/entity/supply/{receipt_id}', auth=auth)
        if response.status_code == 200:
            receipt = response.json()
            return render_template('edit_receipt.html', receipt=receipt)
        else:
            flash('Ошибка при получении данных приёмки для редактирования.')
            return redirect(url_for('get_receipts'))

@app.route('/api/token', methods=['POST'])
def get_moysklad_token():
    data = request.json
    login = data.get('login')
    password = data.get('password')
    token = data.get('token')
    remember = data.get('remember', False)

    try:
        if token:
            # Проверяем валидность токена через API МойСклад
            app.logger.info(f'Попытка авторизации по токену')
            response = requests.get(
                'https://api.moysklad.ru/api/remap/1.2/entity/employee',
                headers={
                    'Authorization': f'Bearer {token}',
                    'Accept-Encoding': 'gzip'
                }
            )
        elif login and password:
            # Если передан логин и пароль, получаем токен через Basic Auth
            app.logger.info(f'Попытка авторизации по логину/паролю')
            credentials = base64.b64encode(f"{login}:{password}".encode()).decode()
            response = requests.post(
                'https://api.moysklad.ru/api/remap/1.2/security/token',
                headers={
                    'Authorization': f'Basic {credentials}',
                    'Accept-Encoding': 'gzip'
                }
            )
        else:
            app.logger.error('Не предоставлены данные для авторизации')
            return jsonify({
                'error': 'Необходимо указать токен или логин/пароль',
                'code': 'Unauthorized'
            }), 401

        if response.status_code == 200:
            if token:
                token_value = token
            else:
                token_data = response.json()
                token_value = token_data['access_token']
            
            # Сохраняем токен в сессии
            session['ms_token'] = token_value
            app.logger.info(f'Токен успешно сохранен в сессии')
            
            # Создаем или получаем пользователя
            username = login or 'token_user'
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, password=password or '', remember_credentials=remember)
                db.session.add(user)
                db.session.commit()
                app.logger.info(f'Создан новый пользователь: {username}')
            elif remember:
                user.remember_credentials = True
                if password:
                    user.password = password
                db.session.commit()
                app.logger.info(f'Обновлены данные пользователя: {username}')

            # Создаем новый токен в БД
            new_token = Token(
                access_token=token_value,
                user_id=user.id,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(new_token)
            db.session.commit()
            app.logger.info(f'Токен сохранен в базе данных')

            session['user_id'] = user.id
            
            return jsonify({
                'success': True,
                'access_token': token_value,
                'remember': remember,
                'redirect': url_for('supplies_page')
            })
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка авторизации: {error_data}')
            return jsonify({
                'error': error_data.get('error', 'Ошибка авторизации'),
                'code': error_data.get('code', 'Unauthorized'),
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при авторизации: {str(e)}')
        return jsonify({
            'error': 'Неожиданная ошибка при авторизации',
            'code': 'InternalServerError',
            'details': str(e)
        }), 500

@app.route('/api/supplies', methods=['GET'])
def get_supplies():
    """Получение списка приемок из МойСклад"""
    try:
        # Проверяем авторизацию
        if 'user_id' not in session:
            app.logger.error('Пользователь не авторизован')
            return jsonify({
                'error': 'Необходима авторизация',
                'code': 'Unauthorized'
            }), 401

        # Получаем токен из БД
        user = User.query.get(session['user_id'])
        if not user:
            app.logger.error(f'Пользователь не найден: {session["user_id"]}')
            return jsonify({
                'error': 'Пользователь не найден',
                'code': 'UserNotFound'
            }), 401

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()
        if not token or token.is_expired():
            app.logger.error('Токен истек или не найден')
            return jsonify({
                'error': 'Необходима повторная авторизация',
                'code': 'TokenExpired'
            }), 401

        # Формируем заголовки запроса
        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip'
        }

        # Запрос к API МойСклад
        url = 'https://api.moysklad.ru/api/remap/1.2/entity/supply'
        app.logger.info(f'Отправка запроса к МойСклад: {url}')
        
        response = requests.get(url, headers=headers)
        app.logger.info(f'Получен ответ от МойСклад: {response.status_code}')

        if response.status_code == 200:
            supplies = response.json()
            app.logger.info(f'Успешно получены приемки. Количество: {len(supplies.get("rows", []))}')
            return jsonify(supplies)
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при получении приемок: {error_data}')
            return jsonify({
                'error': 'Ошибка при получении списка приемок',
                'code': error_data.get('code', 'UnknownError'),
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении приемок: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'code': 'InternalServerError',
            'details': str(e)
        }), 500

@app.route('/api/supplies', methods=['POST'])
def create_supply():
    """Создание новой приёмки"""
    try:
        if 'user_id' not in session:
            app.logger.error('Пользователь не авторизован')
            return jsonify({
                'error': 'Необходима авторизация',
                'code': 'Unauthorized'
            }), 401

        user = db.session.get(User, session['user_id'])
        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        data = request.json
        app.logger.info(f'Попытка создания приёмки. Данные: {data}')

        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            'https://api.moysklad.ru/api/remap/1.2/entity/supply',
            headers=headers,
            json=data
        )

        if response.status_code == 200:
            app.logger.info('Приёмка успешно создана')
            return jsonify(response.json())
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при создании приёмки: {error_data}')
            return jsonify(error_data), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при создании приёмки: {str(e)}')
        return jsonify({
            'error': str(e),
            'code': 'InternalServerError'
        }), 500

@app.route('/api/supplies/<string:supply_id>', methods=['PUT'])
def update_supply(supply_id):
    """Обновление приёмки"""
    try:
        if 'user_id' not in session:
            app.logger.error('Пользователь не авторизован')
            return jsonify({
                'error': 'Необходима авторизация',
                'code': 'Unauthorized'
            }), 401

        user = db.session.get(User, session['user_id'])  # Используем новый метод session.get()
        if not user:
            app.logger.error(f'Пользователь не найден: {session["user_id"]}')
            return jsonify({
                'error': 'Пользователь не найден',
                'code': 'UserNotFound'
            }), 401

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()
        if not token or token.is_expired():
            app.logger.error('Токен истек или не найден')
            return jsonify({
                'error': 'Необходима повторная авторизация',
                'code': 'TokenExpired'
            }), 401

        data = request.json
        app.logger.info(f'Попытка обновления приёмки {supply_id}. Данные: {data}')

        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip',
            'Content-Type': 'application/json'
        }

        response = requests.put(
            f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}',
            headers=headers,
            json=data
        )

        app.logger.info(f'Ответ от МойСклад: {response.status_code}')

        if response.status_code == 200:
            app.logger.info(f'Приёмка {supply_id} успешно обновлена')
            return jsonify(response.json())
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при обновлении приёмки: {error_data}')
            return jsonify({
                'error': 'Ошибка при обновлении приёмки',
                'code': error_data.get('code', 'UnknownError'),
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при обновлении приёмки: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'code': 'InternalServerError',
            'details': str(e)
        }), 500

@app.route('/api/supplies/<string:supply_id>', methods=['DELETE'])
def delete_supply(supply_id):
    """Удаление приёмки"""
    try:
        if 'user_id' not in session:
            app.logger.error('Пользователь не авторизован')
            return jsonify({
                'error': 'Необходима авторизация',
                'code': 'Unauthorized'
            }), 401

        user = db.session.get(User, session['user_id'])
        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip'
        }

        response = requests.delete(
            f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}',
            headers=headers
        )

        if response.status_code == 200:
            app.logger.info(f'Приёмка {supply_id} успешно удалена')
            return jsonify({'success': True})
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при удалении приёмки: {error_data}')
            return jsonify(error_data), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при удалении приёмки: {str(e)}')
        return jsonify({
            'error': str(e),
            'code': 'InternalServerError'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")