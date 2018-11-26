from flask import (
    Flask, request, render_template,
    redirect, url_for, session, g, abort)
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
    Form, TextAreaField, StringField,
    PasswordField, validators, ValidationError)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import hashlib
import sqlite3
import os
from functools import wraps
import datetime
import re

app = Flask(__name__)
mail = Mail(app)

# # #
# CONFIG
#

# secrets
app.secret_key = os.urandom(16)  # keeping this random as it is on public github
app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)  # keeping this random as it is on public github
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LethXwUAAAAAOpsqvH8g--kWSBBRY1ia_zBlaL1'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LethXwUAAAAAEqRb8XvXnGGA2VQsW1RPl0Fkgal'


# security settings
app.debug = False  # no debugging - do not show user stack trace!!!!
app.config['WTF_CSRF_ENABLED'] = False

# mail settings
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'secureblogconfirmmailing@gmail.com'
app.config['MAIL_PASSWORD'] = 'secureblogpassword1'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


# # #
# SECURITY
#

# registration email confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


# html character escaping dictionary
html_dict = {"!": "&#33;",
             "\"": "&#34;",
             "#": "&#35;",
             "$": "&#36;",
             "%": "&#37;",
             "&": "&#38;",
             "'": "&#39;",
             "(": "&#40;",
             ")": "&#41;",
             "*": "&#42;",
             "+": "&#43;",
             ",": "&#44;",
             "-": "&#45;",
             ".": "&#46;",
             "/": "&#47;",
             ":": "&#58;",
             ";": "&#59;",
             "<": "&#60;",
             "=": "&#61;",
             ">": "&#62;",
             "?": "&#63;",
             "@": "&#64;",
             "[": "&#91;",
             "\\": "&#92;",
             "]": "&#93;",
             "^": "&#94;",
             "_": "&#95;",
             "`": "&#96;",
             "{": "&#123;",
             "|": "&#124;",
             "}": "&#125;",
             "~": "&#126;",
             "€": "&#128;",
             "‚": "&#130;",
             "ƒ": "&#131;",
             "„": "&#132;",
             "…": "&#133;",
             "†": "&#134;",
             "‡": "&#135;",
             "ˆ": "&#136;",
             "‰": "&#137;",
             "Š": "&#138;",
             "‹": "&#139;",
             "Œ": "&#140;",
             "Ž": "&#142;",
             "‘": "&#145;",
             "’": "&#146;",
             "“": "&#147;",
             "”": "&#148;",
             "•": "&#149;",
             "–": "&#150;",
             "—": "&#151;",
             "™": "&#153;",
             "š": "&#154;",
             "›": "&#155;",
             "œ": "&#156;",
             "ž": "&#158;",
             "Ÿ": "&#159;",
             "¡": "&#161;",
             "¢": "&#162;",
             "£": "&#163;",
             "¤": "&#164;",
             "¥": "&#165;",
             "¦": "&#166;",
             "§": "&#167;",
             "¨": "&#168;",
             "©": "&#169;",
             "ª": "&#170;",
             "«": "&#171;",
             "¬": "&#172;",
             "­": "&#173;",
             "®": "&#174;",
             "¯": "&#175;",
             "°": "&#176;",
             "±": "&#177;",
             "²": "&#178;",
             "³": "&#179;",
             "´": "&#180;",
             "µ": "&#181;",
             "¶": "&#182;",
             "·": "&#183;",
             "¸": "&#184;",
             "¹": "&#185;",
             "º": "&#186;",
             "»": "&#187;",
             "¼": "&#188;",
             "½": "&#189;",
             "¾": "&#190;",
             "¿": "&#191;",
             "À": "&#192;",
             "Á": "&#193;",
             "Â": "&#194;",
             "Ã": "&#195;",
             "Ä": "&#196;",
             "Å": "&#197;",
             "Æ": "&#198;",
             "Ç": "&#199;",
             "È": "&#200;",
             "É": "&#201;",
             "Ê": "&#202;",
             "Ë": "&#203;",
             "Ì": "&#204;",
             "Í": "&#205;",
             "Î": "&#206;",
             "Ï": "&#207;",
             "Ð": "&#208;",
             "Ñ": "&#209;",
             "Ò": "&#210;",
             "Ó": "&#211;",
             "Ô": "&#212;",
             "Õ": "&#213;",
             "Ö": "&#214;",
             "×": "&#215;",
             "Ø": "&#216;",
             "Ù": "&#217;",
             "Ú": "&#218;",
             "Û": "&#219;",
             "Ü": "&#220;",
             "Ý": "&#221;",
             "Þ": "&#222;",
             "ß": "&#223;",
             "à": "&#224;",
             "á": "&#225;",
             "â": "&#226;",
             "ã": "&#227;",
             "ä": "&#228;",
             "å": "&#229;",
             "æ": "&#230;",
             "ç": "&#231;",
             "è": "&#232;",
             "é": "&#233;",
             "ê": "&#234;",
             "ë": "&#235;",
             "ì": "&#236;",
             "í": "&#237;",
             "î": "&#238;",
             "ï": "&#239;",
             "ð": "&#240;",
             "ñ": "&#241;",
             "ò": "&#242;",
             "ó": "&#243;",
             "ô": "&#244;",
             "õ": "&#245;",
             "ö": "&#246;",
             "÷": "&#247;",
             "ø": "&#248;",
             "ù": "&#249;",
             "ú": "&#250;",
             "û": "&#251;",
             "ü": "&#252;",
             "ý": "&#253;",
             "þ": "&#254;",
             "ÿ": "&#255;"}

# sets up the mapping for the html escaping
html_sorted = sorted(html_dict, key=lambda s: len(s[0]), reverse=True)
html_escaped = [re.escape(replacement) for replacement in html_sorted]
html_pattern = re.compile("|".join(html_escaped))


# User input is escaped and returned
def escape(user_input):
    return html_pattern.sub(lambda match: html_dict[match.group(0)], user_input)


# decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# # #
# CSRF Protection
#
# new token generated per-request
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(400)


def generate_csrf_token():
    if '_csrf_token' not in session:
        # generate per-request CSRF token
        session['_csrf_token'] = hashlib.sha3_512(os.urandom(128)).hexdigest()
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def std_context(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        context = {}
        request.context = context
        if 'username' in session:
            context['loggedin'] = True
            context['username'] = session['username']
        else:
            context['loggedin'] = False
        return f(*args, **kwargs)

    return wrapper


# # #
# INDEX
#

@app.route('/')
@std_context
def index():
    posts = get_index_posts()

    def fix(item):
        item['DATE'] = datetime.datetime.fromtimestamp(item['DATE']).strftime('%Y-%m-%d %H:%M')
        item['CONTENT'] = '%s...' % (item['CONTENT'][:200])
        return item

    context = request.context
    if posts:
        context['posts'] = map(fix, posts)
    else:
        context['posts'] = posts

    return render_template('index.html', context=context)


@app.route('/search/')
@std_context
def search_page():
    context = request.context
    search_query = request.args.get('s', '')
    posts = search_posts(search_query)

    if posts:
        for post in posts:
            post['CONTENT'] = '%s...' % (post['CONTENT'][:50])
        context['posts'] = posts
    context['query'] = search_query
    return render_template('search_results.html', context=context)


# # #
# USER ACCOUNTS
#

default_account_error = u'There was an error with the account credentials'


class PasswordValidator(object):
    def __init__(self, message=None):
        if not message:
            message = u'Password must contain at least one uppercase character and one number'
        self.message = message

    def __call__(self, form, field):
        str = field.data
        if not re.search('\d.*[A-Z]|[A-Z].*\d', str):
            raise ValidationError(self.message)


# user forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired(),
    ])
    email = StringField('Email Address', [
        validators.Email(),
    ])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.length(min=8, message='Password must be 8 or more characters'),
        PasswordValidator()
    ])
    confirm = PasswordField('Repeat Password')
    recaptcha = RecaptchaField()
    registration_error = 'Unable to register account using these credentials'

    # override validate to ensure username and email are unique
    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        if not check_if_username_exists(self.username.data) and check_if_email_exists(self.email.data):
            # use same error message in same location with random delay - ACCOUNT ENUMERATION PROTECTION
            enumeration_delay()
            self.confirm.errors.append(self.registration_error)
            return False

        return True


class LoginForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired('Please enter your username')
    ])
    password = PasswordField('Password', [
        validators.DataRequired('Please enter your password')
    ])
    recaptcha = RecaptchaField()
    login_error = 'Unable to login using these credentials'

    # override validation to include credentials check
    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        if not validate_credentials(self.username.data, self.password.data):
            # use same error message in same location with random delay - ACCOUNT ENUMERATION PROTECTION
            enumeration_delay()
            self.password.errors.append(self.login_error)
            return False

        return True


class ForgotPasswordForm(Form):
    email = StringField('Email Address', validators=[
        validators.DataRequired('Please enter your email address.'),
        validators.Email()
    ])
    recaptcha = RecaptchaField()


class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', validators=[
        validators.DataRequired()
    ])
    password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.length(min=8, message='Password must be 8 or more characters'),
        PasswordValidator()
    ])
    confirm = PasswordField('Repeat Password')

    # override validation to include credentials check
    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        if not validate_credentials(session['username'], self.old_password.data):
            # use same error message in same location with random delay - ACCOUNT ENUMERATION PROTECTION
            enumeration_delay()
            self.old_password.errors.append(default_account_error)
            return False

        return True


class ResetPasswordForm(Form):
    password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.length(min=8, message='Password must be 8 or more characters'),
        PasswordValidator()
    ])
    confirm = PasswordField('Repeat Password')

    # override validation to include credentials check
    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        if 0 == 1:
            # use same error message in same location with random delay - ACCOUNT ENUMERATION PROTECTION
            enumeration_delay()
            self.old_password.errors.append(default_account_error)
            return False

        return True


# used to stop account enumeration using retrieval time to make guesses
def enumeration_delay():
    from time import sleep
    import random
    # sleep from 0.2 to 0.6 seconds
    sleep(random.uniform(0.2, 0.6))


class PostForm(Form):
    title = StringField('Title', validators=[
        validators.DataRequired()
    ])
    content = TextAreaField('Content', validators=[
        validators.DataRequired()
    ])


@app.route('/register', methods=['GET', 'POST'])
@std_context
def register():
    context = request.context
    if context['loggedin']:
        return redirect(url_for('index'))
    form = RegistrationForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        username = escape(form.username.data)
        email = form.email.data
        password = form.password.data

        # hash password for storage
        hashed_password = hashlib.sha3_512(str.encode(password))
        add_user_to_database(username, hashed_password.hexdigest(), email)

        # create and send confirmation email
        html = render_template('confirmation_email.html', confirm_url='/confirm/'+generate_confirmation_token(email))
        subject = 'Please confirm your email'
        mail.send(Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[email], body=html))

        return render_template('registration_confirm.html', context=context)

    return render_template('registration.html', form=form, context=context)


@app.route('/login', methods=['GET', 'POST'])
@std_context
def login():
    context = request.context
    if context['loggedin']:
        return redirect(url_for('index'))
    form = LoginForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        if not user_confirmed(get_userid(form.username.data)):
            context['basicmessage'] = 'Please confirm your email before logging in.'
            return render_template('basic.html', context=context)
        session['username'] = form.username.data
        return redirect(url_for('index'))
    return render_template('login.html', form=form, context=context)


@app.route('/logout')
@std_context
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/confirm/<token>')
@std_context
def confirm_email(token):
    context = request.context
    try:
        email = confirm_token(token)
    except:
        context['basicmessage'] = 'The confirmation link is invalid or has expired.'
        return render_template('basic.html', context=context)
    username = get_username(email)
    userid = get_userid(username)
    if user_confirmed(userid):
        context['basicmessage'] = 'Account already confirmed. Please login.'
    else:
        confirm_user(userid)
        context['basicmessage'] = 'You have confirmed your account. Please login.'
    return render_template('basic.html', context=context)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
@std_context
def change_password():
    context = request.context
    form = ChangePasswordForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        hashed_password = hashlib.sha3_512(str.encode(form.password.data))
        change_password(get_userid(session['username']), hashed_password.hexdigest())
        context['basicmessage'] = 'Password successfully changed!'
        return render_template('basic.html', context=context)
    return render_template('password_change.html', form=form, context=context)


@app.route('/forgot-password', methods=['GET', 'POST'])
@std_context
def forgot_password():
    context = request.context
    if 'username' in session:
        context['basicmessage'] = 'You are already signed in.'
        return render_template('basic.html', context=context)
    # send email regardless - ACCOUNT ENUMERATION PROTECTION
    form = ForgotPasswordForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        email = form.email.data
        # create and send reset email
        html = render_template('password_reset_email.html',
                               reset_url='/reset-password/' + generate_confirmation_token(email))
        subject = 'Forgotten Password - Reset Your Password'
        mail.send(Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[email], body=html))
        context['basicmessage'] = 'An email has been sent to the address provided.'
        return render_template('basic.html', context=context)
    return render_template('forgot_password.html', form=form, context=context)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@std_context
def reset_password(token):
    context = request.context
    if 'username' in session:
        context['basicmessage'] = 'You are already signed in.'
        return render_template('basic.html', context=context)
    try:
        email = confirm_token(token)
        if not email:
            context['basicmessage'] = 'The link is invalid or has expired.'
            return render_template('basic.html', context=context)
    except:
        context['basicmessage'] = 'The link is invalid or has expired.'
        return render_template('basic.html', context=context)
    if not check_if_email_exists(email):
        # return blank page for non users - ACCOUNT ENUMERATION PROTECTION
        return render_template('basic.html')
    print(email)
    username = get_username(email)
    userid = get_userid(username)
    form = ResetPasswordForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        hashed_password = hashlib.sha3_512(str.encode(form.password.data))
        change_password(userid, hashed_password.hexdigest())
        context['basicmessage'] = 'Password successfully reset! Please login to continue.'
        return render_template('basic.html', context=context)
    return render_template('password_reset.html', form=form, context=context)


# # #
# POSTS
#
@app.route('/u/<uname>/')
@std_context
def users_posts(uname=None):
    context = request.context
    if not check_if_username_exists(uname):
        return render_template('basic.html', context=context)

    def fix(item):
        item['DATE'] = datetime.datetime.fromtimestamp(item['DATE']).strftime('%Y-%m-%d %H:%M')
        return item

    posts = get_user_posts(get_userid(uname))
    if posts:
        context['posts'] = map(fix, posts)
    else:
        context['posts'] = posts
    return render_template('user_posts.html', context=context)


@app.route('/post/', methods=['GET', 'POST'])
@std_context
@login_required
def new_post():
    context = request.context
    userid = get_userid(session['username'])
    form = PostForm(request.form, meta={'csrf': False})
    if request.method == 'POST' and form.validate():
        date = datetime.datetime.now().timestamp()
        title = escape(form.title.data)
        content = escape(form.content.data)
        add_post_to_database(userid, date, title, content)
        return redirect('/u/' + session['username'])

    return render_template('new_post.html', form=form, context=context)


# # #
# DATABASE FUNCTIONS
#

DATABASE = 'blogsite.sqlite'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts

    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def validate_credentials(username, password):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME = ?", (username,))
        rows = cursor.fetchall()
        if not rows:
            return rows
        stored_password = rows[0]['PASSWORD']

        # we're comparing the hashes rather than passwords themselves - we don't actually store the password
        hash_of_entered_password = hashlib.sha3_512(str.encode(password)).hexdigest()

        return stored_password == hash_of_entered_password


def check_if_username_exists(username):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS")
        rows = cursor.fetchall()
    return any(username in user_dict['USERNAME'] for user_dict in rows)


def check_if_email_exists(email):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS")
        rows = cursor.fetchall()
    return any(email in user_dict['EMAIL'] for user_dict in rows)


def add_user_to_database(username, password, email):
    connection = get_db()
    confirmed = 0
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT MAX(USERID) FROM USERS")
        userid = (cursor.fetchone()['MAX(USERID)']) + 1
        cursor.execute("INSERT INTO USERS VALUES (?, ?, ?, ?, ?)", (userid, username, password, email, confirmed))


def user_confirmed(userid):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS WHERE CONFIRMED = 1")
        rows = cursor.fetchall()
    return any(userid == user_dict['USERID'] for user_dict in rows)


def confirm_user(userid):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("UPDATE USERS SET CONFIRMED = 1 WHERE USERID = ?", (userid,))


def change_password(userid, new_password_hash):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("UPDATE USERS SET PASSWORD = ? WHERE USERID = ?", (new_password_hash, userid))


def get_userid(username):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT USERID FROM USERS WHERE USERNAME = ?", (username,))
        userid = cursor.fetchone()['USERID']
    return userid


def get_username(email):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS WHERE EMAIL = ?", (email,))
        username = cursor.fetchone()['USERNAME']
    return username


def get_user_posts(userid):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT DATE,TITLE,CONTENT FROM POSTS WHERE CREATOR = ? ORDER BY DATE DESC", (userid,))
        rows = cursor.fetchall()
    return rows if rows else None


def get_index_posts():
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        statement = '''SELECT POSTS.CREATOR,POSTS.DATE,POSTS.TITLE,POSTS.CONTENT,USERS.USERNAME 
        FROM POSTS JOIN USERS ON POSTS.CREATOR=USERS.USERID ORDER BY DATE DESC LIMIT 10'''
        cursor.execute(statement)
        rows = cursor.fetchall()
    return rows if rows else None


def search_posts(query):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute('SELECT POSTS.CREATOR,POSTS.TITLE,POSTS.CONTENT,USERS.USERNAME FROM POSTS JOIN USERS ' +
                       'ON POSTS.CREATOR=USERS.USERID WHERE TITLE LIKE ? ORDER BY DATE DESC LIMIT 10;', (query,))
        rows = cursor.fetchall()
    return rows if rows else None


def add_post_to_database(userid, date, title, content):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT MAX(POSTID) FROM POSTS")
        postid = (cursor.fetchone()['MAX(POSTID)']) + 1
        cursor.execute("INSERT INTO POSTS (POSTID, CREATOR, DATE, TITLE, CONTENT) VALUES (?, ?, ?, ?, ?)",
                       (postid, userid, date, title, content))


if __name__ == '__main__':
    app.run()
