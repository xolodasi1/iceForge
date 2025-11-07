import os
import re
from flask import (Flask, render_template, request, redirect, url_for,
                   send_from_directory, session, flash, jsonify, abort)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime # <-- Добавлен импорт

# --- Настройка ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_MOD_EXTENSIONS = {'jar', 'zip'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'a_very_secret_and_random_string_for_my_project_v3'

# --- Имитация баз данных ---
users_db = {}
mods_db = []
mod_id_counter = 0

# --- Вспомогательные функции ---
def get_next_mod_id():
    global mod_id_counter
    mod_id_counter += 1
    return mod_id_counter

def get_youtube_embed_url(url):
    if not url: return None
    regex = r"(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+\/|(?:v|e(?:mbed)?)\/|\S*?[?&]v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})"
    match = re.search(regex, url)
    return f"https://www.youtube.com/embed/{match.group(1)}" if match else None

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Для доступа к этой странице необходимо войти в аккаунт.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Роуты для пользователей ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            flash("Пользователь с таким именем уже существует!")
            return redirect(url_for('register'))

        users_db[username] = {
            'password': generate_password_hash(password),
            'description': 'Это мое описание по умолчанию.',
            'avatar': 'default.png'
        }

        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], username, 'mods'), exist_ok=True)
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], username, 'images'), exist_ok=True)
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], username, 'avatars'), exist_ok=True)

        flash("Аккаунт успешно создан! Теперь вы можете войти.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = users_db.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            session['username'] = username
            flash(f"Добро пожаловать, {username}!")
            return redirect(url_for('index'))
        else:
            flash("Неверное имя пользователя или пароль.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Вы вышли из аккаунта.")
    return redirect(url_for('index'))

# --- Роуты для аккаунта ---
@app.route('/account')
@login_required
def account():
    username = session['username']
    user_data = users_db.get(username)
    user_mods = [mod for mod in mods_db if mod['author'] == username]
    return render_template('account.html', user=user_data, mods=user_mods)

@app.route('/account/update', methods=['POST'])
@login_required
def update_account():
    username = session['username']
    users_db[username]['description'] = request.form.get('description')
    flash("Профиль успешно обновлен.")
    return redirect(url_for('account'))

@app.route('/account/avatar', methods=['POST'])
@login_required
def update_avatar():
    username = session['username']
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], username, 'avatars', filename)
            file.save(save_path)
            users_db[username]['avatar'] = filename
            flash("Аватар успешно обновлен.")
    return redirect(url_for('account'))

# --- Основные роуты сайта ---
@app.route('/')
def index():
    # Получаем значения фильтров из URL
    selected_version = request.args.get('version', '')
    selected_loader = request.args.get('loader', '')
    selected_dependency = request.args.get('dependency', '')

    # Формируем списки для выпадающих меню фильтров, убирая дубликаты
    available_versions = sorted(list(set(mod['version'] for mod in mods_db)))
    # Используем .get(), чтобы избежать ошибок на старых модах без этих полей
    available_loaders = sorted(list(set(mod.get('loader') for mod in mods_db if mod.get('loader'))))
    available_dependencies = sorted(list(set(mod.get('dependency') for mod in mods_db if mod.get('dependency'))))

    # Последовательно применяем фильтры
    filtered_mods = mods_db
    if selected_version:
        filtered_mods = [mod for mod in filtered_mods if mod.get('version') == selected_version]
    if selected_loader:
        filtered_mods = [mod for mod in filtered_mods if mod.get('loader') == selected_loader]
    if selected_dependency:
        filtered_mods = [mod for mod in filtered_mods if mod.get('dependency') == selected_dependency]

    return render_template(
        'index.html',
        mods=filtered_mods,
        versions=available_versions,
        loaders=available_loaders,
        dependencies=available_dependencies,
        selected_version=selected_version,
        selected_loader=selected_loader,
        selected_dependency=selected_dependency
    )
def get_file_size(file_path):
    """Вспомогательная функция для получения размера файла в читаемом формате."""
    try:
        size_bytes = os.path.getsize(file_path)
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{round(size_bytes / 1024, 2)} KB"
        else:
            return f"{round(size_bytes / (1024**2), 2)} MB"
    except FileNotFoundError:
        return "N/A"

@app.route('/mod/<int:mod_id>')
def mod_details(mod_id):
    mod = next((mod for mod in mods_db if mod['id'] == mod_id), None)
    if mod is None: abort(404)

    # Получаем информацию о файле
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], mod['author'], 'mods', mod['filename'])
    file_size = get_file_size(file_path)

    embed_url = get_youtube_embed_url(mod.get('video_url'))

    # Передаем новые данные в шаблон
    return render_template('mod_page.html', mod=mod, embed_url=embed_url, file_size=file_size)

@app.route('/mod/<int:mod_id>/comment', methods=['POST'])
@login_required
def add_comment(mod_id):
    mod = next((mod for mod in mods_db if mod['id'] == mod_id), None)
    if mod is None: abort(404)
    comment_text = request.form.get('comment_text')
    if comment_text:
        mod['comments'].append({'author': session['username'], 'text': comment_text})
        flash("Ваш комментарий добавлен!")
    else:
        flash("Текст комментария не может быть пустым.")
    return redirect(url_for('mod_details', mod_id=mod_id))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_page():
    if request.method == 'POST':
        current_user = session['username']
        mod_images = request.files.getlist('mod_images')

        if not mod_images or mod_images[0].filename == '':
            return jsonify({'status': 'error', 'message': 'Вы должны загрузить хотя бы одно изображение.'}), 400

        if 'mod_file' not in request.files or request.files['mod_file'].filename == '':
            return jsonify({'status': 'error', 'message': 'Не выбран файл мода'}), 400

        mod_file = request.files['mod_file']

        image_filenames = []
        for image_file in mod_images:
            if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], current_user, 'images', filename))
                image_filenames.append(filename)
            else:
                return jsonify({'status': 'error', 'message': 'Одно или несколько изображений имеют неверный формат.'}), 400

        if mod_file and allowed_file(mod_file.filename, ALLOWED_MOD_EXTENSIONS):
            mod_filename = secure_filename(mod_file.filename)
            mod_file.save(os.path.join(app.config['UPLOAD_FOLDER'], current_user, 'mods', mod_filename))

            new_mod = {
                'id': get_next_mod_id(),
                'name': request.form['mod_name'],
                'version': request.form['mod_version'],
                'description': request.form['mod_description'],
                'filename': mod_filename,
                'image_filenames': image_filenames,
                'author': current_user,
                'video_url': request.form.get('video_url', ''),
                'comments': [],
                'upload_date': datetime.now().strftime("%d.%m.%Y"),
                'loader': request.form['mod_loader'], # <-- НОВАЯ СТРОКА
                'dependency': request.form['mod_dependency'] # <-- НОВАЯ СТРОКА
            }
            mods_db.append(new_mod)
            return jsonify({'status': 'success', 'redirect_url': url_for('index')})
        else:
            return jsonify({'status': 'error', 'message': 'Неверный тип файла мода'}), 400

    return render_template('upload.html')

# В файле app.py

@app.route('/edit_mod/<int:mod_id>', methods=['GET', 'POST'])
@login_required
def edit_mod(mod_id):
    mod = next((m for m in mods_db if m['id'] == mod_id), None)
    if not mod or mod['author'] != session['username']:
        flash("Мод не найден или у вас нет прав на его редактирование.")
        return redirect(url_for('account'))

    if request.method == 'POST':
        # Обновляем текстовые данные и селекторы
        mod['name'] = request.form['mod_name']
        mod['version'] = request.form['mod_version']
        mod['description'] = request.form['mod_description']
        mod['video_url'] = request.form.get('video_url', '')
        mod['loader'] = request.form['mod_loader']
        mod['dependency'] = request.form['mod_dependency']

        # --- НАЧАЛО НОВОЙ ЛОГИКИ ОБРАБОТКИ ФАЙЛА ---
        if 'mod_file' in request.files:
            new_file = request.files['mod_file']

            # Проверяем, что пользователь действительно выбрал новый файл
            if new_file and new_file.filename != '':
                if allowed_file(new_file.filename, ALLOWED_MOD_EXTENSIONS):
                    # 1. Определяем путь к старому файлу
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], mod['author'], 'mods', mod['filename'])

                    # 2. Безопасно удаляем старый файл
                    try:
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                    except OSError as e:
                        print(f"Error deleting old file: {e}")
                        flash("Ошибка при удалении старого файла мода.")
                        return redirect(url_for('edit_mod', mod_id=mod_id))

                    # 3. Сохраняем новый файл
                    new_filename = secure_filename(new_file.filename)
                    new_file.save(os.path.join(app.config['UPLOAD_FOLDER'], mod['author'], 'mods', new_filename))

                    # 4. Обновляем имя файла в нашей "базе данных"
                    mod['filename'] = new_filename
                else:
                    flash("Неверный тип файла для обновления мода. Разрешены .jar и .zip")
                    return redirect(url_for('edit_mod', mod_id=mod_id))
        # --- КОНЕЦ НОВОЙ ЛОГИКИ ОБРАБОТКИ ФАЙЛА ---

        flash("Мод успешно обновлен.")
        return redirect(url_for('mod_details', mod_id=mod_id))

    return render_template('edit_mod.html', mod=mod)
@app.route('/delete_mod/<int:mod_id>', methods=['POST'])
@login_required
def delete_mod(mod_id):
    mod_to_delete = None
    for i, mod in enumerate(mods_db):
        if mod['id'] == mod_id and mod['author'] == session['username']:
            mod_to_delete = mod
            del mods_db[i]
            break

    if mod_to_delete:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], mod_to_delete['author'], 'mods', mod_to_delete['filename']))
            for img in mod_to_delete['image_filenames']:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], mod_to_delete['author'], 'images', img))
        except OSError as e:
            print(f"Error deleting files: {e}")
        flash("Мод успешно удален.")
    else:
        flash("Мод не найден или у вас нет прав на его удаление.")

    return redirect(url_for('account'))


# --- Роуты для отдачи файлов ---
@app.route('/uploads/<username>/mods/<filename>')
def download_file(username, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], username, 'mods'), filename, as_attachment=True)

@app.route('/uploads/<username>/images/<filename>')
def serve_image(username, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], username, 'images'), filename)

@app.route('/uploads/<username>/avatars/<filename>')
def serve_avatar(username, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], username, 'avatars'), filename)

@app.route('/static/images/<filename>')
def serve_default_avatar(filename):
    return send_from_directory(os.path.join('static', 'images'), filename)


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)