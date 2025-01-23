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

    user = db.session.get(User, session['user_id'])
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
def save_token():
    try:
        app.logger.info('Получены данные для сохранения токена')
        app.logger.info(f'Headers: {request.headers}')
        app.logger.info(f'Data: {request.get_data()}')
        
        # Проверяем наличие пользователя в сессии
        if 'user_id' not in session:
            app.logger.error('Отсутствует user_id в сессии')
            return jsonify({'error': 'Unauthorized'}), 401

        # Пробуем получить данные из разных источников
        if request.is_json:
            data = request.get_json()
            app.logger.info('Получены JSON данные')
        else:
            try:
                data = request.form.to_dict()
                app.logger.info('Получены form данные')
            except:
                data = {}
                app.logger.error('Не удалось получить данные из формы')

        # Проверяем наличие токена в данных
        access_token = data.get('access_token')
        if not access_token:
            app.logger.error('Отсутствует access_token в данных')
            return jsonify({'error': 'Token is required'}), 400

        app.logger.info('Попытка авторизации по токену')
        
        # Получаем пользователя
        user = db.session.get(User, session['user_id'])
        if not user:
            app.logger.error(f'Пользователь не найден: {session["user_id"]}')
            return jsonify({'error': 'User not found'}), 404

        # Сохраняем токен в сессии
        session['access_token'] = access_token
        app.logger.info('Токен успешно сохранен в сессии')

        # Сохраняем токен в базе данных
        token = Token(
            user_id=user.id,
            access_token=access_token
        )
        db.session.add(token)
        db.session.commit()
        app.logger.info('Токен сохранен в базе данных')

        return jsonify({'message': 'Token saved successfully'})

    except Exception as e:
        app.logger.error(f'Ошибка при сохранении токена: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    try:
        is_authenticated = 'user_id' in session and 'access_token' in session
        user = None
        if is_authenticated:
            user = db.session.get(User, session['user_id'])
            is_authenticated = user is not None

        return jsonify({
            'authenticated': is_authenticated,
            'user': user.username if user else None
        })
    except Exception as e:
        app.logger.error(f'Ошибка при проверке статуса авторизации: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/supplies', methods=['GET'])
def get_supplies_list():
    try:
        if 'user_id' not in session:
            return jsonify({
                'error': 'Необходима авторизация',
                'code': 'Unauthorized'
            }), 401

        # Обновляем использование get()
        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip'
        }

        response = requests.get(
            'https://api.moysklad.ru/api/remap/1.2/entity/supply',
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            supplies = data.get('rows', [])
            
            formatted_supplies = []
            for supply in supplies:
                formatted_supply = {
                    'id': supply.get('id'),
                    'name': supply.get('name'),
                    'organization': supply.get('organization', {}).get('name'),
                    'sum': supply.get('sum', 0) / 100,  # Конвертируем копейки в рубли
                    'created': supply.get('created'),
                    'href': supply.get('meta', {}).get('href')
                }
                formatted_supplies.append(formatted_supply)

            return jsonify(formatted_supplies)
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при получении приёмок: {error_data}')
            return jsonify({
                'error': 'Ошибка при получении списка приёмок',
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении приёмок: {str(e)}')
        app.logger.error(f'Детали ответа API: {response.text if "response" in locals() else "Нет данных"}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

@app.route('/api/supplies/<supply_id>', methods=['GET'])
def get_supply_details(supply_id):
    """Получение детальной информации о конкретной приёмке"""
    try:
        if 'user_id' not in session:
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

        # Получаем основную информацию о приёмке с expand для организации и склада
        response = requests.get(
            f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}',
            headers=headers,
            params={
                'expand': 'organization,store'
            }
        )

        if response.status_code == 200:
            supply = response.json()
            app.logger.info(f'Получены данные приёмки: {supply}')
            
            # Получаем позиции приёмки
            positions_response = requests.get(
                f'https://api.moysklad.ru/api/remap/1.2/entity/supply/{supply_id}/positions',
                headers=headers,
                params={
                    'expand': 'assortment'
                }
            )
            
            positions = []
            if positions_response.status_code == 200:
                positions_data = positions_response.json()
                app.logger.info(f'Получены позиции приёмки: {positions_data}')
                if 'rows' in positions_data:
                    positions = positions_data['rows']
            
            # Форматируем данные приёмки
            formatted_supply = {
                'id': supply.get('id'),
                'name': supply.get('name'),
                # Получаем имя организации из развернутого объекта
                'organization': supply.get('organization', {}).get('name') if supply.get('organization') else None,
                # Получаем имя склада из развернутого объекта
                'store': supply.get('store', {}).get('name') if supply.get('store') else None,
                'sum': supply.get('sum', 0) / 100,
                'vatEnabled': supply.get('vatEnabled', False),
                'vatIncluded': supply.get('vatIncluded', False),
                'vatSum': supply.get('vatSum', 0) / 100,
                'created': supply.get('created'),
                'positions': []
            }
            
            # Форматируем позиции
            for pos in positions:
                assortment = pos.get('assortment', {})
                position = {
                    'name': assortment.get('name') if assortment else 'Неизвестный товар',
                    'quantity': pos.get('quantity', 0),
                    'price': pos.get('price', 0) / 100,
                    'vat': pos.get('vat', 0),
                    'vatEnabled': pos.get('vatEnabled', False),
                    'discount': pos.get('discount', 0),
                    'total': (pos.get('quantity', 0) * pos.get('price', 0)) / 100
                }
                formatted_supply['positions'].append(position)

            app.logger.info(f'Отформатированные данные приёмки: {formatted_supply}')
            return jsonify(formatted_supply)
        else:
            error_data = response.json()
            app.logger.error(f'Ошибка при получении приёмки: {error_data}')
            return jsonify({
                'error': 'Ошибка при получении приёмки',
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении приёмки: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
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