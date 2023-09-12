import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db


bp = Blueprint('auth', __name__, url_prefix='/authentication')
bp1 = Blueprint('blog', __name__, url_prefix='/blog')
bp_home = Blueprint('home', __name__)


@bp1.route('/')
def index():
    return render_template('blog/index.html')

@bp.route('/')
def index_auth():
    return render_template('auth/index.html')

@bp_home.route('/')
def index_home():
    return render_template('index.html')


@bp.route('/register', methods=['post', 'get'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        if not username:
            error = 'Username is required!'
        elif not password:
            error = 'Password is required!'
        if error is None:
            try:
                db.execute("INSERT INTO user(username, password) VALUES (?, ?)", username, generate_password_hash(password))
                db.commit()
            except db.IntegrityError as ex:
                # print(f'An exception occured: {str(ex)}')
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
        flash(error)
    return render_template('auth/register.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM `user` WHERE `username` = ?', (username,)).fetchone()
        
        if user is None:
            error = 'Incorrect Username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect Password'
        if error is None:
            session.clear()
            session['use_id'] = user['id']
            return redirect(url_for('index'))
        
        flash(error)
    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM `user` WHERE id = ?', (user_id,)).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view