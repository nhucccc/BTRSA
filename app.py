from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import os, json, hashlib, datetime
from rsa_utils import generate_keys, sign_file, verify_signature

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'user_files'
RECEIVED_FOLDER = 'received_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

USERS_FILE = 'users.json'
HISTORY_FILE = 'history.json'

# Helper
def load_users():
    if not os.path.exists(USERS_FILE): return {}
    with open(USERS_FILE) as f: return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f: json.dump(users, f, indent=2)

def load_history():
    if not os.path.exists(HISTORY_FILE): return []
    with open(HISTORY_FILE) as f: return json.load(f)

def save_history(history):
    with open(HISTORY_FILE, 'w') as f: json.dump(history, f, indent=2)

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        users = load_users()
        if username in users:
            flash("Tài khoản đã tồn tại!")
            return redirect(url_for('register'))

        private_key, public_key = generate_keys()
        users[username] = {
            'password': password,
            'private_key': private_key.decode(),
            'public_key': public_key.decode()
        }
        save_users(users)
        os.makedirs(os.path.join(UPLOAD_FOLDER, username), exist_ok=True)
        os.makedirs(os.path.join(RECEIVED_FOLDER, username), exist_ok=True)
        flash("Đăng ký thành công!")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash("Sai tài khoản hoặc mật khẩu!")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    users = load_users()
    user_files = os.listdir(os.path.join(RECEIVED_FOLDER, username))
    return render_template('dashboard.html', users=users.keys(), files=user_files, current=username)

@app.route('/send', methods=['POST'])
def send():
    sender = session['username']
    receiver = request.form['receiver']
    file = request.files['file']

    users = load_users()
    if receiver not in users:
        flash("Người nhận không tồn tại.")
        return redirect(url_for('dashboard'))

    # Lưu file tạm thời
    filepath = os.path.join(UPLOAD_FOLDER, sender, file.filename)
    file.save(filepath)

    # Ký file
    signature = sign_file(filepath, users[sender]['private_key'].encode())

    # Gửi file và chữ ký sang thư mục của người nhận
    recv_path = os.path.join(RECEIVED_FOLDER, receiver, file.filename)
    sig_path = recv_path + '.sig'

    with open(recv_path, 'wb') as f_out:
        with open(filepath, 'rb') as f_in:
            f_out.write(f_in.read())
    with open(sig_path, 'wb') as sig_file:
        sig_file.write(signature)

    # Lưu lịch sử
    history = load_history()
    history.append({
        'from': sender,
        'to': receiver,
        'file': file.filename,
        'status': 'Pending',
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    save_history(history)

    flash("Gửi file thành công!")
    return redirect(url_for('dashboard'))

@app.route('/verify/<filename>')
def verify(filename):
    user = session['username']
    users = load_users()
    file_path = os.path.join(RECEIVED_FOLDER, user, filename)
    sig_path = file_path + '.sig'

    # Tìm lịch sử để biết ai gửi
    sender = None
    for entry in load_history():
        if entry['to'] == user and entry['file'] == filename:
            sender = entry['from']
            break

    if not sender or sender not in users:
        flash("Không tìm thấy người gửi.")
        return redirect(url_for('dashboard'))

    with open(sig_path, 'rb') as f:
        signature = f.read()

    is_valid = verify_signature(file_path, signature, users[sender]['public_key'].encode())
    flash("Chữ ký hợp lệ!" if is_valid else "Chữ ký không hợp lệ!")

    # Cập nhật lịch sử
    history = load_history()
    for entry in history:
        if entry['from'] == sender and entry['to'] == user and entry['file'] == filename:
            entry['status'] = 'Verified' if is_valid else 'Invalid'
            break
    save_history(history)

    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download(filename):
    user = session['username']
    path = os.path.join(RECEIVED_FOLDER, user)
    return send_from_directory(path, filename, as_attachment=True)

@app.route('/history')
def history():
    user = session['username']
    all_history = [h for h in load_history() if h['from'] == user or h['to'] == user]
    return render_template('history.html', history=all_history)

if __name__ == '__main__':
    app.run(debug=True)
