from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'istinye-university-security-2026-abdulilah'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


def get_encryption_key():
    key_file = 'encryption_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        new_key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(new_key)
        return new_key


encryption_key = get_encryption_key()
cipher = Fernet(encryption_key)


def encrypt_data(plain_text):
    if not plain_text:
        return None
    return cipher.encrypt(plain_text.encode()).decode()


def decrypt_data(encrypted_text):
    if not encrypted_text:
        return None
    return cipher.decrypt(encrypted_text.encode()).decode()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')

    national_id_encrypted = db.Column(db.Text)
    phone_encrypted = db.Column(db.Text)

    full_name = db.Column(db.String(100))
    department = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_national_id(self):
        return decrypt_data(self.national_id_encrypted)

    def get_phone(self):
        return decrypt_data(self.phone_encrypted)


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
    grade_encrypted = db.Column(db.Text, nullable=False)

    student = db.relationship('User', foreign_keys=[student_id])
    teacher = db.relationship('User', foreign_keys=[teacher_id])

    def get_grade(self):
        return decrypt_data(self.grade_encrypted)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in allowed_roles:
                flash('Access denied. You do not have permission to view this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name').strip()
        national_id = request.form.get('national_id').strip()
        phone = request.form.get('phone').strip()
        department = request.form.get('department').strip()

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            department=department,
            role='student',
            national_id_encrypted=encrypt_data(national_id),
            phone_encrypted=encrypt_data(phone)
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))


@app.route('/student/dashboard')
@role_required('student')
def student_dashboard():
    grades = Grade.query.filter_by(student_id=current_user.id).all()

    decrypted_grades = []
    for g in grades:
        decrypted_grades.append({
            'course': g.course_name,
            'grade': g.get_grade(),
            'teacher': g.teacher.full_name
        })

    profile = {
        'national_id': current_user.get_national_id(),
        'phone': current_user.get_phone()
    }

    return render_template('student_dashboard.html',
                           grades=decrypted_grades,
                           profile=profile)


@app.route('/teacher/dashboard')
@role_required('teacher')
def teacher_dashboard():
    students = User.query.filter_by(role='student').all()
    my_grades = Grade.query.filter_by(teacher_id=current_user.id).all()

    grades_list = []
    for g in my_grades:
        grades_list.append({
            'id': g.id,
            'student_name': g.student.full_name,
            'course': g.course_name,
            'grade': g.get_grade()
        })

    return render_template('teacher_dashboard.html',
                           students=students,
                           grades=grades_list)


@app.route('/teacher/add-grade', methods=['POST'])
@role_required('teacher')
def add_grade():
    student_id = request.form.get('student_id')
    course_name = request.form.get('course_name').strip()
    grade_value = request.form.get('grade').strip()

    student = User.query.filter_by(id=student_id, role='student').first()
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))

    new_grade = Grade(
        student_id=student.id,
        teacher_id=current_user.id,
        course_name=course_name,
        grade_encrypted=encrypt_data(grade_value)
    )

    db.session.add(new_grade)
    db.session.commit()

    flash(f'Grade added successfully for {student.full_name}.', 'success')
    return redirect(url_for('teacher_dashboard'))


@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    all_users = User.query.all()
    total_grades = Grade.query.count()

    users_data = []
    for u in all_users:
        users_data.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'full_name': u.full_name,
            'role': u.role,
            'department': u.department,
            'national_id': u.get_national_id(),
            'phone': u.get_phone()
        })

    stats = {
        'total_users': len(all_users),
        'total_students': sum(1 for u in all_users if u.role == 'student'),
        'total_teachers': sum(1 for u in all_users if u.role == 'teacher'),
        'total_admins': sum(1 for u in all_users if u.role == 'admin'),
        'total_grades': total_grades
    }

    return render_template('admin_dashboard.html',
                           users=users_data,
                           stats=stats)


@app.route('/admin/change-role/<int:user_id>', methods=['POST'])
@role_required('admin')
def change_role(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin_dashboard'))

    new_role = request.form.get('new_role')
    if new_role not in ['admin', 'teacher', 'student']:
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin_dashboard'))

    user.role = new_role
    db.session.commit()

    flash(f'Role updated for {user.full_name} to {new_role}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_dashboard'))

    Grade.query.filter_by(student_id=user.id).delete()
    Grade.query.filter_by(teacher_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    flash(f'User {user.full_name} has been deleted.', 'info')
    return redirect(url_for('admin_dashboard'))


def initialize_database():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(role='admin').first():
            default_admin = User(
                username='admin',
                email='admin_abdulilah@istinye.edu.tr',
                full_name='Abdulilah Admin',
                department='IT Administration',
                role='admin',
                national_id_encrypted=encrypt_data('00000000000'),
                phone_encrypted=encrypt_data('+90 000 000 0000')
            )
            default_admin.set_password('Admin@123')
            db.session.add(default_admin)
            db.session.commit()
            print('Default admin created: admin_abdulilah@istinye.edu.tr / Admin@123')


if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)