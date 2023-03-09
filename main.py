from random import randint
from flask import Flask, render_template, request, flash, send_from_directory, url_for
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = '91ccfaa6a7c03e6b1c297ee21bbb1432bbaf9363d52a185aab2657baa8c7ddbb'


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get((int(user_id)))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = User()
        user.name = request.form['name']
        user.email = request.form['email']
        password = request.form['password']
        error = None
        # Check if the email is already registered
        if User.query.filter_by(email=user.email).first():
            flash("You've already signed up with that email, log in instead!", 'error')
            return redirect(url_for('login'))

        # Salting and Hashing Passwords
        salt_length = randint(16, 32)
        user.password = generate_password_hash(
            password,
            method='pbkdf2:sha3_512:100000',
            salt_length=salt_length
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("secrets"))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        existing_user = User.query.filter_by(email=request.form['email']).first()
        if existing_user:
            if check_password_hash(existing_user.password, request.form['password']):
                login_user(existing_user)
                flash('You were successfully logged in!', 'success')
                return redirect(url_for('secrets'))
            else:
                flash('Invalid Credentials', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid Credentials', 'error')
            return redirect(url_for('login'))
    return render_template("login.html")


login_manager.login_view = "login"


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static/files', filename='cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
