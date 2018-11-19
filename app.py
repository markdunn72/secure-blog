from flask import (
    Flask, request, render_template,
    redirect, url_for, flash, session, g)
from wtforms import Form, BooleanField, StringField, PasswordField, validators
import hashlib
import sqlite3
import os
from functools import wraps
import datetime

app = Flask(__name__)


#html character escaping dictionary
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
             " ": "&#152;",
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

#sets up the mapping for the html escaping
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
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


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

    for post in posts:
        post['content'] = '%s...'%(post['content'][:50])
    context['posts'] = posts
    context['query'] = search_query
    return render_template('search_results.html', context=context)


# # #
# USER ACCOUNTS
#
default_account_error = u'There was an error with the account credentials'


# user forms
class RegistrationForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
    ])
    email = StringField('Email Address', [
        validators.Email(),
    ])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    registration_error = 'Unable to register account using these credentials'

    # override validation to ensure username and email are unique
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


class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired('Please enter your username')
    ])
    password = PasswordField('Password', [
        validators.DataRequired('Please enter your password')
    ])
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


# used to stop account enumeration using retrieval time to make guesses
def enumeration_delay():
    from time import sleep
    import random
    # sleep from 0.2 to 0.6 seconds
    sleep(random.uniform(0.2, 0.6))


@app.route('/register', methods=['GET', 'POST'])
@std_context
def register():
    context = request.context
    if context['loggedin']:
        return redirect(url_for('index'))
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # hash password for storage
        hashed_password = hashlib.sha3_512(str.encode(password))
        add_user_to_database(username, hashed_password.hexdigest(), email)
        session['username'] = username
        return redirect(url_for('login'))

    return render_template('registration.html', form=form, context=context)


@app.route('/login', methods=['GET', 'POST'])
@std_context
def login():
    context = request.context
    if context['loggedin']:
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        session['username'] = form.username.data
        return redirect(url_for('index'))

    return render_template('login.html', form=form, context=context)


@app.route('/logout')
@std_context
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/<uname>/')
@std_context
def users_posts(uname=None):
    if not check_if_username_exists(uname):
        return 'RETURN MOCK USER_POSTS PAGE WITH FALSE UNAME'

    def fix(item):
        item['DATE'] = datetime.datetime.fromtimestamp(item['DATE']).strftime('%Y-%m-%d %H:%M')
        return item

    context = request.context
    posts = get_user_posts(get_userid(uname))

    if posts:
        context['posts'] = map(fix, posts)
    else:
        context['posts'] = posts

    return render_template('user_posts.html', context=context)


# # #
# DATABASE FUNCTIONS
#
# secured by using parameterized statements and appcontext teardown of db
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
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT MAX(USERID) FROM USERS")
        userid = (cursor.fetchone()['MAX(USERID)']) + 1
        cursor.execute("INSERT INTO USERS VALUES (?, ?, ?, ?)", (userid, username, password, email))


def get_userid(username):
    connection = get_db()
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT USERID FROM USERS WHERE USERNAME = ?", (username,))
        userid = cursor.fetchone()['USERID']
    return userid


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
        statement = '''SELECT POSTS.CREATOR,POSTS.TITLE,POSTS.CONTENT,USERS.USERNAME FROM POSTS JOIN USERS 
        ON POSTS.CREATOR=USERS.USERID WHERE TITLE LIKE '%%?%%' ORDER BY DATE DESC LIMIT 10;'''
        cursor.execute(statement, (query,))
        rows = cursor.fetchall()
    return rows if rows else None


if __name__ == '__main__':
    # secure session key
    app.secret_key = os.urandom(16)
    # set debug=False for production
    app.run(debug=True)
