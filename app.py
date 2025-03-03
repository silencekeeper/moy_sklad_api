from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import logging
from logging.handlers import RotatingFileHandler
import os
import json
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
from flask import session
from flask_login import UserMixin
import base64
from datetime import datetime, timedelta
import pudb
import uuid
from flask_migrate import Migrate

# Создаем приложение Flask
app = Flask(__name__)

# Конфигурация приложения
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moysklad.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=True)
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
    
class Supply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    counterparty_href = db.Column(db.String(255), nullable=False)
    external_code = db.Column(db.String(255), nullable=False)
    milk_mass = db.Column(db.Float, nullable=False)
    fat_percent = db.Column(db.Float, nullable=False)
    protein_percent = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    fat_kg = db.Column(db.Float, nullable=False)
    protein_kg = db.Column(db.Float, nullable=False)
    vat_included = db.Column(db.Boolean, nullable=False)
    store_href = db.Column(db.String(255), nullable=False, default=False)
    organization_href = db.Column(db.String(255), nullable=False, default=False)
    
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    moysklad_id = db.Column(db.String(255), unique=True)  # Добавляем поле moysklad_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('organizations', lazy=True))

class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    moysklad_id = db.Column(db.String(255), unique=True)  # Добавляем поле moysklad_id
    name = db.Column(db.String(255), nullable=False)
    href = db.Column(db.String(255), nullable=False)

# Создаем директорию для логов, если её нет
if not os.path.exists('logs'):
    os.makedirs('logs')

# Настраиваем логирование
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)

# Файловый обработчик
file_handler = RotatingFileHandler(
    'logs/moysklad.log',
    maxBytes=10240000,
    backupCount=5,
    encoding='utf-8'
)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# Консольный обработчик
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# Настраиваем логгер приложения
app.logger.addHandler(file_handler)
app.logger.addHandler(console_handler)
app.logger.setLevel(logging.INFO)

app.logger.info('Приложение запущено')

load_dotenv()


# Создаем таблицы при запуске
with app.app_context():
    db.create_all()

TOKEN = "02bf2b522f9bb7671245b1c825e9d669a7cd581a"

headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}"
}

MOYSKLAD_API_URL = 'https://api.moysklad.ru/api/remap/1.2'
auth = HTTPBasicAuth(os.getenv('MOYSKLAD_LOGIN'), os.getenv('MOYSKLAD_PASSWORD'))

# Пример данных, которые могут быть возвращены
counterparties = [
    {"id": "1", "name": "Контрагент 1"},
    {"id": "2", "name": "Контрагент 2"}
]

organizations = [
    {"id": "1", "name": "Организация 1"},
    {"id": "2", "name": "Организация 2"}
]

warehouses = [
    {"id": "1", "name": "Склад 1"},
    {"id": "2", "name": "Склад 2"}
]

products = [
    {"id": "1", "name": "Товар 1"},
    {"id": "2", "name": "Товар 2"}
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/supplies')
def supplies_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('supplies.html')

@app.route('/supplies/new', methods=['GET'])
def new_supply():
    logging.debug("Отображение страницы создания новой приёмки")
    return render_template('new_supply.html')

@app.route('/api/token', methods=['POST'])
def save_token():
    """Сохранение токена доступа"""
    try:
        app.logger.info('Получены данные для сохранения токена')
        app.logger.info(f'Headers: {request.headers}')
        app.logger.info(f'Data: {request.get_data()}')
        
        # Получаем данные из запроса
        data = request.get_json()
        if not data or 'access_token' not in data:
            app.logger.error('Отсутствует токен в запросе')
            return jsonify({
                'error': 'Отсутствует токен в запросе'
            }), 400
            
        access_token = data['access_token']
        
        # Создаем пользователя, если его нет
        user = User.query.filter_by(username='token_user').first()
        if not user:
            user = User(username='token_user')
            db.session.add(user)
            db.session.commit()
            app.logger.info('Создан новый пользователь token_user')
        
        # Сохраняем токен в сессии
        session['ms_token'] = access_token
        session['user_id'] = user.id
        app.logger.info('Токен успешно сохранен в сессии')
        
        # Сохраняем токен в базе данных
        token = Token(
            access_token=access_token,
            user_id=user.id,
            created_at=datetime.utcnow()
        )
        db.session.add(token)
        db.session.commit()
        app.logger.info('Токен сохранен в базе данных')
        
        return jsonify({'message': 'Token saved successfully'})
        
    except Exception as e:
        app.logger.error(f'Ошибка при сохранении токена: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

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
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        store_href = request.args.get('store')
        
        query = Supply.query.filter_by(user_id=user.id)
        if store_href:
            query = query.filter_by(store_href=store_href)
        supplies = query.order_by(Supply.created_at.desc()).all()

        stores = Store.query.filter_by(user_id=user.id).all()

        formatted_supplies = []
        for supply in supplies:
            store_name = next((s.name for s in stores if s.href == supply.store_href), 'Неизвестный склад')
            counterparty_name = next((c.name for c in user.counterparties if c.href == supply.counterparty_href), 'Неизвестный контрагент')
            formatted_supply = {
                'id': supply.id,
                'store_name': store_name,
                'created_at': supply.created_at.isoformat(),
                'counterparty_name': counterparty_name,
                'milk_mass': supply.milk_mass,
                'fat_percent': supply.fat_percent,
                'protein_percent': supply.protein_percent,
                'price': supply.price,
                'fat_kg': supply.fat_kg,
                'protein_kg': supply.protein_kg,
                'vat_included': supply.vat_included
            }
            formatted_supplies.append(formatted_supply)

        return jsonify({
            'supplies': formatted_supplies,
            'stores': [{'name': s.name, 'href': s.href} for s in stores]
        })

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении приёмок: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

def get_product_name(product_href, headers):
    """Получает наименование продукта по ссылке"""
    try:
        response = requests.get(product_href, headers=headers)
        if response.status_code == 200:
            product_data = response.json()
            return product_data.get('name', 'Неизвестный продукт')
        else:
            app.logger.error(f'Ошибка при получении продукта: {response.status_code}')
            return 'Неизвестный продукт'
    except Exception as e:
        app.logger.error(f'Ошибка при запросе продукта: {str(e)}')
        return 'Неизвестный продукт'

@app.route('/api/supplies/<supply_id>', methods=['GET'])
def get_supply_details(supply_id):
    """Получение детальной информации о конкретной приёмке"""
    try:
        app.logger.info(f'\n\n=== ЗАПРОС ДЕТАЛЕЙ ПРИЁМКИ {supply_id} ===')
        
        if 'user_id' not in session:
            app.logger.error('Отсутствует user_id в сессии')
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

        url = f'{MOYSKLAD_API_URL}/entity/supply/{supply_id}'
        params = {
            'expand': 'organization,store,agent,positions'
        }

        app.logger.info(f'Отправка запроса к МойСклад:')
        app.logger.info(f'URL: {url}')
        app.logger.info(f'Параметры: {params}')
        app.logger.info(f'Заголовки: {headers}')

        # Получаем основную информацию о приёмке
        response = requests.get(url, headers=headers, params=params)
        
        app.logger.info(f'Получен ответ от сервера. Статус: {response.status_code}')
        app.logger.info(f'Заголовки ответа: {dict(response.headers)}')
        
        try:
            response_data = response.json()
            app.logger.info('\n=== ОТВЕТ СЕРВЕРА (НАЧАЛО) ===\n')
            app.logger.info(json.dumps(response_data, ensure_ascii=False, indent=2))
            app.logger.info('\n=== ОТВЕТ СЕРВЕРА (КОНЕЦ) ===\n')
        except Exception as e:
            app.logger.error(f'Ошибка при парсинге JSON: {str(e)}')
            app.logger.error(f'Тело ответа: {response.text}')
            raise

        if response.status_code == 200:
            supply = response_data
            
            # Форматируем данные приёмки
            formatted_supply = {
                'id': supply.get('id'),
                'name': supply.get('name'),
                'organization': supply.get('organization', {}).get('name'),
                'store': supply.get('store', {}).get('name'),
                'agent': supply.get('agent', {}).get('name'),
                'sum': supply.get('sum', 0) / 100,
                'vatEnabled': supply.get('vatEnabled', False),
                'vatIncluded': supply.get('vatIncluded', False),
                'vatSum': supply.get('vatSum', 0) / 100,
                'created': supply.get('created'),
                'positions': []
            }
            
            # Обрабатываем позиции
            if 'positions' in supply:
                positions_data = supply['positions']
                app.logger.info('\n=== ПОЗИЦИИ ПРИЁМКИ ===\n')
                app.logger.info(json.dumps(positions_data, ensure_ascii=False, indent=2))
                
                if isinstance(positions_data, dict) and 'rows' in positions_data:
                    for pos in positions_data['rows']:
                        assortment_meta = pos.get('assortment', {}).get('meta', {})
                        product_href = assortment_meta.get('href')
                        product_name = get_product_name(product_href, headers) if product_href else 'Неизвестный продукт'
                        
                        position = {
                            'name': product_name,
                            'quantity': pos.get('quantity', 0),
                            'price': pos.get('price', 0) / 100,
                            'vat': pos.get('vat', 0),
                            'vatEnabled': pos.get('vatEnabled', False),
                            'discount': pos.get('discount', 0),
                            'total': (pos.get('quantity', 0) * pos.get('price', 0)) / 100
                        }
                        formatted_supply['positions'].append(position)

            app.logger.info('\n=== ОТФОРМАТИРОВАННЫЕ ДАННЫЕ ===\n')
            app.logger.info(json.dumps(formatted_supply, ensure_ascii=False, indent=2))
            
            # Принудительно сбрасываем буфер логов
            for handler in app.logger.handlers:
                handler.flush()
                
            return jsonify(formatted_supply)
        else:
            error_data = response_data
            app.logger.error(f'Ошибка при получении приёмки: {error_data}')
            return jsonify({
                'error': 'Ошибка при получении приёмки',
                'details': error_data
            }), response.status_code

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении приёмки: {str(e)}')
        if 'response' in locals():
            app.logger.error(f'Тело ответа при ошибке: {response.text}')
        # Принудительно сбрасываем буфер логов
        for handler in app.logger.handlers:
            handler.flush()
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

@app.route('/api/supplies', methods=['POST'])
def create_supplies():
    try:
        if 'user_id' not in session:
            app.logger.error('Пользователь не авторизован')
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            app.logger.error(f'Пользователь не найден: {session["user_id"]}')
            return jsonify({'error': 'Пользователь не найден'}), 401

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()
        if not token:
            app.logger.error('Токен не найден')
            return jsonify({'error': 'Необходима авторизация'}), 401

        data = request.get_json()
        supplies = []
        created_supplies = []

        for supply_data in data:
            # Генерируем уникальный external_code
            external_code = str(uuid.uuid4())
            
            supply = {
                "organization": supply_data.get('organization', ''),
                "agent": supply_data.get('agent', ''),
                "store": supply_data.get('store', ''),
                'moment': supply_data.get('moment', ''),
                "externalCode": external_code,
                "positions": []
            }

            # Добавляем позиции для жира и белка
            supply['positions'].append({
                "quantity": supply_data.get('fatKg',''),
                "price": supply_data.get('fatPrice',''),
                "assortment": {
                    "meta": {
                        "href": "https://api.moysklad.ru/api/remap/1.2/entity/product/87ed8bde-bfb9-11ef-0a80-18f3001bf494",
                        "type": "product",
                        "mediaType": "application/json"
                    }
                }
            })
            supply['positions'].append({
                "quantity": supply_data.get('proteinKg',''),
                "price": supply_data.get('proteinPrice',''),
                "assortment": {
                    "meta": {
                        "href": "https://api.moysklad.ru/api/remap/1.2/entity/product/a5623ead-bfb9-11ef-0a80-1654001bdea7",
                        "type": "product",
                        "mediaType": "application/json"
                    }
                }
            })

            supplies.append(supply)
            created_supplies.append({"external_code": external_code})

        url = f'{MOYSKLAD_API_URL}/entity/supply'
        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept': 'application/json;charset=utf-8',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, headers=headers, json=supplies)
        
        if response.ok:
            # Сохраняем информацию о созданных приёмках в базу
            response_data = response.json()
            for i, supply_info in enumerate(response_data):
                supply = Supply(
                    external_code=created_supplies[i]["external_code"],
                    moysklad_id=supply_info["id"],
                    user_id=user.id
                )
                db.session.add(supply)
            db.session.commit()
            
            return jsonify({'message': 'Приёмки успешно созданы'}), 200
        else:
            app.logger.error(f'Ошибка при создании приёмок: {response.status_code} {response.text}')
            return jsonify({'error': f'Ошибка при создании приёмок: {response.status_code} {response.text}'}), response.status_code

    except Exception as e:
        app.logger.error(f"Неизвестная ошибка: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
            f'{MOYSKLAD_API_URL}/entity/supply/{supply_id}',
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
            f'{MOYSKLAD_API_URL}/entity/supply/{supply_id}',
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

@app.route('/api/counterparties', methods=['GET'])
def get_counterparties():
    logging.debug("Получение списка контрагентов из API МойСклад")
    
    user = db.session.get(User, session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

    headers = {
        'Authorization': f'Bearer {token.access_token}',
        'Accept-Encoding': 'gzip'
    }
    
    url = f"{MOYSKLAD_API_URL}/entity/counterparty"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        counterparties = response.json()["rows"]
        return jsonify([{"id": c["id"], "name": c["name"]} for c in counterparties])
    else:
        logging.error(f"Ошибка при получении контрагентов: {response.status_code} {response.text}")
        return jsonify([])

@app.route('/api/warehouses', methods=['GET'])
def get_warehouses():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        warehouses = Store.query.filter_by(user_id=user.id).all()

        return jsonify([{
            'id': w.moysklad_id,
            'name': w.name,
            'href': w.href
        } for w in warehouses])

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении складов: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500
@app.route('/api/update_organizations', methods=['POST'])
def update_organizations():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        url = f"{MOYSKLAD_API_URL}/entity/organization"
        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip'
        }
        response = requests.get(url, headers=headers)

        if response.ok:
            organizations_data = response.json()["rows"]
            
            # Сохраняем организации в базу данных
            for org_data in organizations_data:
                org = Organization.query.filter_by(moysklad_id=org_data["id"]).first()
                if not org:
                    org = Organization(name=org_data["name"], moysklad_id=org_data["id"], user_id=user.id)
                    db.session.add(org)
                else:
                    org.name = org_data["name"]
            db.session.commit()

            return jsonify({'message': 'Список организаций успешно обновлен'})
        else:
            logging.error(f"Ошибка при обновлении организаций: {response.status_code} {response.text}")
            return jsonify({'error': 'Не удалось обновить список организаций'}), 500

    except Exception as e:
        logging.exception("Ошибка при обновлении организаций")
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

@app.route('/api/update_warehouses', methods=['POST'])
def update_warehouses():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        url = f"{MOYSKLAD_API_URL}/entity/store"
        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Accept-Encoding': 'gzip'
        }
        response = requests.get(url, headers=headers)
        
        if response.ok:
            warehouses_data = response.json()["rows"]
            print(warehouses_data)

            # Сохраняем склады в базу данных  
            for w_data in warehouses_data:
                warehouse = Store.query.filter_by(moysklad_id=w_data["id"]).first()
                if not warehouse:
                    warehouse = Store(name=w_data["name"], moysklad_id=w_data["id"], user_id=user.id, href=w_data["meta"]["href"])
                    db.session.add(warehouse)
                else:
                    warehouse.name = w_data["name"]
            db.session.commit()

            return jsonify({'message': 'Список складов успешно обновлен'})
        else:
            logging.error(f"Ошибка при обновлении складов: {response.status_code} {response.text}")
            return jsonify({'error': 'Не удалось обновить список складов'}), 500

    except Exception as e:
        logging.exception("Ошибка при обновлении складов")
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e) 
        }), 500
        
@app.route('/api/organizations', methods=['GET'])
def get_organizations():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Необходима авторизация'}), 401

        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        organizations = Organization.query.filter_by(user_id=user.id).all()

        return jsonify([{
            'name': o.name,
            'id': o.moysklad_id
        } for o in organizations])

    except Exception as e:
        app.logger.error(f'Неожиданная ошибка при получении организаций: {str(e)}')
        return jsonify({
            'error': 'Внутренняя ошибка сервера',
            'details': str(e)
        }), 500

@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        user = db.session.get(User, session['user_id'])
        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()

        headers = {
            'Authorization': f'Bearer {token.access_token}',
            'Content-Type': 'application/json'
        }
        
        url = f'{MOYSKLAD_API_URL}/entity/product?limit=100'
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            products = response.json()['rows']
            
            result = []
            for p in products:                
                product = {
                    'id': p['id'],
                    'name': p.get('name', ''),
                    'code': p.get('code', ''),
                }
                
                if p.get('uom'):
                    uom_url = p['uom']['meta']['href']
                    uom_response = requests.get(uom_url, headers=headers)
                    if uom_response.status_code == 200:
                        product['uom'] = uom_response.json()['name']
                    else:
                        product['uom'] = ''
                        print(f"Ошибка при получении единицы измерения: {uom_response.status_code} {uom_response.text}")
                else:
                    product['uom'] = ''
                
                result.append(product)
            
            return jsonify(result), 200
        else:
            error_msg = f"Ошибка при получении списка товаров: {response.status_code} {response.text}"  
            app.logger.error(error_msg)
            return jsonify({'error': error_msg}), response.status_code
        
    except Exception as e:
        app.logger.error(f"Неизвестная ошибка: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/supplies/list', methods=['GET'])
def get_filtered_supplies():
    if 'user_id' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    store_href = request.args.get('store')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = Supply.query.filter_by(user_id=user.id)
    
    if store_href:
        query = query.filter_by(store_href=store_href)
    
    if start_date and end_date:
        query = query.filter(Supply.created_at.between(start_date, end_date))
    
    supplies = query.all()
    
    token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()
    headers = {
        'Authorization': f'Bearer {token.access_token}',
        'Accept': 'application/json;charset=utf-8'
    }
    
    formatted_supplies = []
    for supply in supplies:
        # Получаем данные контрагента по его href
        counterparty_response = requests.get(supply.counterparty_href, headers=headers)
        if counterparty_response.ok:
            counterparty_data = counterparty_response.json()
            counterparty_name = counterparty_data['name']
        else:
            counterparty_name = 'Неизвестный контрагент'
        
        formatted_supply = {
            'id': supply.id,
            'counterparty_name': counterparty_name,
            'milk_mass': supply.milk_mass,
            'fat_percent': supply.fat_percent,
            'protein_percent': supply.protein_percent,
            'fat_kg': supply.fat_kg,
            'protein_kg': supply.protein_kg,
            'price': supply.price,
            'created_at': supply.created_at.isoformat()
        }
        formatted_supplies.append(formatted_supply)
    
    return jsonify(formatted_supplies)

def create_supply(data):
    supply = Supply(
        external_code=data['externalCode'],
        user_id=data['user_id'],
        store_href=data['store']['meta']['href'],
        created_at=data['moment'],
        counterparty_href=data['agent']['meta']['href'],
        milk_mass=data['mass'],
        fat_percent=data['fat'],
        protein_percent=data['protein'],
        fat_kg=data['fatKg'],
        protein_kg=data['proteinKg'],
        price=data['price'],
        vat_included=data.get('vatEnabled', False)  # Значение по умолчанию - False
    )
    db.session.add(supply)
    db.session.commit()
    return supply

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")