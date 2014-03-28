#!flaskenv/bin/python
__author__ = 'ltanady'

from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import make_response, render_template, redirect, jsonify, abort
from werkzeug.security import gen_salt
from werkzeug.exceptions import BadRequest
from flask_oauthlib.provider import OAuth2Provider

from models import db
from models import User, Client, Grant, Token, Task, Log

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.debug = True
    app.secret_key = 'secret'
    app.config.update({
        # 'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
        'SQLALCHEMY_DATABASE_URI': 'postgres://root:Ya8oCFUelG088Ieq@172.17.42.1:49153/db'
    })
    db.init_app(app)
    with app.app_context():
        db.create_all()
    return app

app = create_app()
oauth = OAuth2Provider(app)

@app.errorhandler(400)
def bad_request(error):
    """
    Bad Request response for a request. Takes an error message.
    """
    if isinstance(error, BadRequest):
        return make_response(jsonify({'code': 400, 'error': 'BadRequest'}), 400)
    return make_response(jsonify({'code': 400, 'error': error}), 400)

def ok(message, **kwargs):
    """
    OK response for a request. Takes a message argument and optional named arguments
    for objects.
    """
    response_json = {'code': 200, 'message': message}
    for key, value in kwargs.iteritems():
        response_json.update({key: value})
    return make_response(jsonify(response_json), 200)

# ==============================
# OAuth
# ==============================
def current_user():
    """
    Get current user.
    """
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

@app.route('/', methods=('GET', 'POST'))
def home():
    """
    Let user create account or login.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)

@app.route('/client/new')
def client():
    """
    Creates a new client.
    """
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id=gen_salt(40),
        client_secret=gen_salt(50),
        _redirect_uris='http://localhost:8000/authorized',
        _default_scopes='email',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )

@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant

@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok

@app.route('/oauth/token')
@oauth.token_handler
def access_token():
    return None

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

# ================================================
# This is the api for profile and tasks.
# ================================================
@app.route('/api/me')
@oauth.require_oauth('email')
def me(req):
    user = req.user
    return jsonify(username=user.username)

@app.route('/api/v1/tasks', methods=['GET'])
@oauth.require_oauth()
def get_tasks(req):
    """
    Get all tasks given a user.
    """
    log = Log(ip_address=request.remote_addr, request_url=request.url, request_data=request.data)
    db.session.add(log)
    user = req.user
    if not user:
        return bad_request('invalid user')

    try:
        tasks = Task.query.filter_by(user_id=user.id)
        return ok('Tasks found', tasks=[t.serialize for t in tasks])

    except Exception as e:
        print e.message
        return bad_request('invalid user_id')
    finally:
        db.session.commit()

@app.route('/api/v1/tasks', methods=['POST'])
@oauth.require_oauth()
def create_task(req):
    """
    Create a new task given title, description, done and user.
    """
    log = Log(ip_address=request.remote_addr, request_url=request.url, request_data=request.data)
    db.session.add(log)

    if not request.json:
        return bad_request('invalid json request')
    if not 'title' in request.json:
        return bad_request('missing title')
    if not 'description' in request.json:
        return bad_request('missing description')

    user = req.user
    if not user:
        return bad_request('invalid user')

    try:
        title = request.json['title']
        description = request.json['description']
        task = Task(user_id=user.id, title=title, description=description)
        db.session.add(task)
        db.session.commit()

        return ok('Task created', task=task.serialize)
    except Exception as e:
        print e.message
        return abort(400)
    finally:
        db.session.commit()

@app.route('/api/v1/tasks', methods=['PUT'])
@oauth.require_oauth()
def update_task(req):
    """
    Update a task given id, title, description and done.
    """
    log = Log(ip_address=request.remote_addr, request_url=request.url, request_data=request.data)
    db.session.add(log)

    if not request.json:
        return bad_request('invalid json request')
    if not 'id' in request.json:
        return bad_request('missing task id')
    if not 'title' in request.json:
        return bad_request('missing title')
    if not 'description' in request.json:
        return bad_request('missing description')
    if not 'done' in request.json:
        return bad_request('missing done')

    user = req.user
    task = Task.query.filter(Task.id == request.json['id'], Task.user_id == user.id).first()

    if not user:
        return bad_request('invalid user')
    if not task:
        return bad_request('invalid task')

    try:
        task.title = request.json['title']
        task.description = request.json['description']
        task.done = request.json['done']
        db.session.commit()

        return ok('Task updated', task=task.serialize)
    except Exception as e:
        print e.message
        return abort(400)
    finally:
        db.session.commit()

@app.route('/api/v1/tasks', methods=['DELETE'])
@oauth.require_oauth()
def delete_task(req):
    """
    Delete a task given id.
    """
    log = Log(ip_address=request.remote_addr, request_url=request.url, request_data=request.data)
    db.session.add(log)

    print request.json
    if not request.json:
        return bad_request('invalid json request')
    if not 'id' in request.json:
        return bad_request('missing task id')

    user = req.user
    task = Task.query.filter(Task.id == request.json['id'], Task.user_id == user.id).first()

    if not user:
        return bad_request('invalid user')
    if not task:
        return bad_request('invalid task')

    try:
        db.session.delete(task)
        db.session.commit()

        return ok('Task deleted')
    except Exception as e:
        print e.message
        return abort(400)
    finally:
        db.session.commit()

if __name__ == '__main__':
    app.run()
