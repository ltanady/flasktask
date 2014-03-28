#!flaskenv/bin/python

from flask import Flask, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


CLIENT_ID = 'fpxyQP7BmYBEsnlf6PRSHRejjDf9qOg3yryn3Ur9'
CLIENT_SECRET = 'PCdP5PmIZZjFBF0LXZFlqRByeNf8CzoSJa7VNk1RpY5TuwwBqm'


app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url='http://localhost:5000/api/',
    request_token_url=None,
    access_token_url='http://localhost:5000/oauth/token',
    authorize_url='http://localhost:5000/oauth/authorize'
)

@app.route('/')
def index():
    if 'remote_oauth' in session:
        resp = remote.get('me')
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )

@app.route('/tasks')
def get_tasks():
    if 'remote_oauth' in session:
        resp = remote.get('v1/tasks')
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )

@app.route('/tasks/new')
def create_task():
    if 'remote_oauth' in session:
        resp = remote.post('v1/tasks', content_type='application/json', data='{"title":"Task1", "description":"must be completed today."}')
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )

@app.route('/tasks/<int:task_id>/update')
def update_task(task_id):
    title = 'Task1'
    description = 'Must be done today.'
    done = request.args.get('done')
    data = '{"id": %d, "title": "%s", "description": "%s", "done": %s}' % (task_id, title, description, done)
    print data

    if 'remote_oauth' in session:
        resp = remote.put('v1/tasks', content_type='application/json', data=data)
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )

@app.route('/tasks/<int:task_id>/delete')
def delete_task(task_id):
    if 'remote_oauth' in session:
        data = '{"id": %d}' % task_id
        print data
        resp = remote.delete('v1/tasks', content_type='application/json', data=data)
        return jsonify(resp.data)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )

@app.route('/authorized')
@remote.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    print resp
    session['remote_oauth'] = (resp['access_token'], '')
    return jsonify(oauth_token=resp['access_token'])


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    app.run(host='localhost', port=8000)
