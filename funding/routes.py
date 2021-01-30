import uuid
from datetime import datetime

import requests
from flask import request, redirect, render_template, url_for, flash, make_response, send_from_directory, jsonify, session
from flask_login import login_user , logout_user , current_user
from dateutil.parser import parse as dateutil_parse
from flask_yoloapi import endpoint, parameter

import settings
from funding.factory import app, db, cache
from funding.orm import Proposal, User, Comment

import secrets
import json

@app.route('/')
def index():
    return redirect(url_for('proposals'))


@app.route('/about')
def about():
    return make_response(render_template('about.html'))


@app.route('/api')
def api():
    return make_response(render_template('api.html'))


@app.route('/proposal/add/disclaimer')
def proposal_add_disclaimer():
    return make_response(render_template('proposal/disclaimer.html'))


@app.route('/proposal/add')
def proposal_add():
    if current_user.is_anonymous:
        return make_response(redirect(url_for('login')))
    default_content = settings.PROPOSAL_CONTENT_DEFAULT
    return make_response(render_template('proposal/edit.html', default_content=default_content))


@app.route('/proposal/comment', methods=['POST'])
@endpoint.api(
    parameter('pid', type=int, required=True),
    parameter('text', type=str, required=True),
    parameter('cid', type=int, required=False)
)
def proposal_comment(pid, text, cid):
    if current_user.is_anonymous:
        flash('not logged in', 'error')
        return redirect(url_for('proposal', pid=pid))
    if len(text) <= 3:
        flash('comment too short', 'error')
        return redirect(url_for('proposal', pid=pid))
    try:
        Comment.add_comment(user_id=current_user.id, message=text, pid=pid, cid=cid)
    except Exception as ex:
        flash('Could not add comment: %s' % str(ex), 'error')
        return redirect(url_for('proposal', pid=pid))

    flash('Comment posted.')
    return redirect(url_for('proposal', pid=pid))


@app.route('/proposal/<int:pid>/comment/<int:cid>')
def propsal_comment_reply(cid, pid):
    from funding.orm import Comment
    c = Comment.find_by_id(cid)
    if not c or c.replied_to:
        return redirect(url_for('proposal', pid=pid))
    p = Proposal.find_by_id(pid)
    if not p:
        return redirect(url_for('proposals'))
    if c.proposal_id != p.id:
        return redirect(url_for('proposals'))

    return make_response(render_template('comment_reply.html', c=c, pid=pid, cid=cid))


@app.route('/proposal/<int:pid>')
def proposal(pid):
    p = Proposal.find_by_id(pid=pid)
    if not p:
        return make_response(redirect(url_for('proposals')))
    p.get_comments()
    return make_response(render_template(('proposal/proposal.html'), proposal=p))


@app.route('/api/proposal/add', methods=['POST'])
@endpoint.api(
    parameter('title', type=str, required=True, location='json'),
    parameter('content', type=str, required=True, location='json'),
    parameter('pid', type=int, required=False, location='json'),
    parameter('funds_target', type=str, required=True, location='json'),
    parameter('addr_receiving', type=str, required=True, location='json'),
    parameter('category', type=str, required=True, location='json'),
    parameter('status', type=int, required=True, location='json', default=1)
)
def proposal_api_add(title, content, pid, funds_target, addr_receiving, category, status):
    import markdown2

    if current_user.is_anonymous:
        return make_response(jsonify('err'), 500)

    if len(title) <= 8:
        return make_response(jsonify('title too short'), 500)

    if len(content) <= 20:
        return make_response(jsonify('content too short'), 500)

    if category and category not in settings.FUNDING_CATEGORIES:
        return make_response(jsonify('unknown category'), 500)

    if status not in settings.FUNDING_STATUSES.keys():
        make_response(jsonify('unknown status'), 500)

    if status != 1 and not current_user.admin:
        return make_response(jsonify('no rights to change status'), 500)

    try:
        from funding.bin.anti_xss import such_xss
        content_escaped = such_xss(content)
        html = markdown2.markdown(content_escaped, safe_mode=True)
    except Exception as ex:
        return make_response(jsonify('markdown error'), 500)

    if pid:
        p = Proposal.find_by_id(pid=pid)
        if not p:
            return make_response(jsonify('proposal not found'), 500)

        if p.user.id != current_user.id and not current_user.admin:
            return make_response(jsonify('no rights to edit this proposal'), 500)

        p.headline = title
        p.content = content
        p.html = html
        if addr_receiving:
            p.addr_receiving = addr_receiving
        if category:
            p.category = category

        # detect if an admin moved a proposal to a new status and auto-comment
        if p.status != status and current_user.admin:
            msg = "Moved to status \"%s\"." % settings.FUNDING_STATUSES[status].capitalize()
            try:
                Comment.add_comment(user_id=current_user.id, message=msg, pid=pid, automated=True)
            except:
                pass

        p.status = status
        p.last_edited = datetime.now()
    else:
        try: 
            funds_target = float(funds_target) 
        except Exception as ex:
            return make_response(jsonify('letters detected'),500)
        if funds_target < 1:
            return make_response(jsonify('Proposal asking less than 1 error :)'), 500)
        if len(addr_receiving) not in settings.COIN_ADDRESS_LENGTH:
            return make_response(jsonify(f'Faulty address, should be of length: {" or ".join(map(str, settings.COIN_ADDRESS_LENGTH))}'), 500)

        p = Proposal(headline=title, content=content, category='misc', user=current_user)
        p.html = html
        p.last_edited = datetime.now()
        p.funds_target = funds_target
        p.addr_receiving = addr_receiving
        p.category = category
        p.status = status

        # generate integrated address
        try:
            headers_dict = {
                'X-API-KEY': settings.RPC_HEADER,
                'Content-Type': 'application/json'
            }
            # get primary address
            r = requests.get(settings.RPC_LOCATION + "/addresses/primary", headers=headers_dict)
            r.raise_for_status()
            blob = r.json()
            assert 'address' in blob
            main_address = blob['address']
            paymentID = secrets.token_hex(32) 

            r = requests.get(settings.RPC_LOCATION + f"/addresses/{main_address}/{paymentID}", headers=headers_dict)
            r.raise_for_status()
            blob = r.json()

            assert 'integratedAddress' in blob
            assert len(blob['integratedAddress']) == 186
        except Exception as ex:
            raise

        p.addr_donation = blob['integratedAddress']
        p.payment_id = paymentID

        db.session.add(p)

    db.session.commit()
    db.session.flush()

    # reset cached stuffz
    cache.delete('funding_stats')

    return make_response(jsonify({'url': url_for('proposal', pid=p.id)}))


@app.route('/proposal/<int:pid>/edit')
def proposal_edit(pid):
    p = Proposal.find_by_id(pid=pid)
    if not p:
        return make_response(redirect(url_for('proposals')))

    return make_response(render_template('proposal/edit.html', proposal=p))


@app.route('/search')
@endpoint.api(
    parameter('key', type=str, required=False)
)
def search(key=None):
    if not key:
        return make_response(render_template('search.html', results=None, key='Empty!'))
    results = Proposal.search(key=key)
    return make_response(render_template('search.html', results=results, key=key))


@app.route('/user/<path:name>')
def user(name):
    q = db.session.query(User)
    q = q.filter(User.username == name)
    user = q.first()
    return render_template('user.html', user=user)


@app.route('/proposals')
@endpoint.api(
    parameter('status', type=int, location='args', required=False),
    parameter('page', type=int, location='args', required=False),
    parameter('cat', type=str, location='args', required=False)
)
def proposals(status, page, cat):
    if not isinstance(status, int) and not isinstance(page, int) and not cat:
        # no args, render overview
        proposals = {
            'proposed': Proposal.find_by_args(status=1, limit=10),
            'funding': Proposal.find_by_args(status=2, limit=10),
            'wip': Proposal.find_by_args(status=3, limit=10),
            'completed': Proposal.find_by_args(status=4, limit=10)}
        return make_response(render_template('proposal/overview.html', proposals=proposals))

    try:
        if not isinstance(status, int):
            status = 1
        proposals = Proposal.find_by_args(status=status, cat=cat)
    except:
        return make_response(redirect(url_for('proposals')))

    return make_response(render_template('proposal/proposals.html',
                                         proposals=proposals, status=status, cat=cat))


@app.route('/donate')
def donate():
    data_default = {'sum': 0, 'txs': []}
    cache_key = 'devfund_txs_in'
    data = cache.get(cache_key)
    track_txs = []
    sum_amount = 0.0
    if not data:
        try:
            headers_dict = {
                'X-API-KEY': settings.RPC_HEADER_DEVFUND,
                'Content-Type': 'application/json'
            }
            r = requests.get(settings.RPC_LOCATION_DEVFUND + "/transactions", headers=headers_dict)
            r.raise_for_status()
            blob = r.json()
            assert 'transactions' in blob
            assert isinstance(blob['transactions'], list)
            txs = blob['transactions']
            for tx in txs:
                if 5 < tx['unlockTime'] - tx['blockHeight'] < 500000000 and len(tx['transfers']) > 0 and tx['transfers'][0]['amount'] > 0:
                    track_txs.append({'amount_human': float(tx['transfers'][0]['amount'])/1e2, 'txid': tx['hash'], 'type': 'in', 'block_height': tx['blockHeight'], 'datetime': datetime.fromtimestamp(tx['timestamp'])})
                    sum_amount += float(tx['transfers'][0]['amount'])/1e2
            print(track_txs)
        except Exception as ex:
            return "devfund page error"
        if len(track_txs) == 0:
            cache.set(cache_key, data_default, 15)
        else:
            txs_in = track_txs[:50]
            txs_in_list = {'txs': txs_in, 'sum': sum_amount}
            cache.set(cache_key, txs_in_list, 15)
    else:
        txs_in = data

    return make_response(render_template('donate.html', txs_in=txs_in_list))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if settings.USER_REG_DISABLED:
        return 'user reg disabled ;/'

    if request.method == 'GET':
        return make_response(render_template('register.html'))

    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    try:
        user = User.add(username, password, email)
        flash('Successfully registered. No confirmation email required. You can login!')
        cache.delete('funding_stats')  # reset cached stuffz
        return redirect(url_for('login'))
    except Exception as ex:
        flash('Could not register user. Probably a duplicate username or email that already exists.', 'error')
        return make_response(render_template('register.html'))


if settings.OPENID_ENABLED:
    @app.route("/fund-auth/")
    def wow_auth():
        assert "state" in request.args
        assert "session_state" in request.args
        assert "code" in request.args

        # verify state
        if not session.get('auth_state'):
            return "session error", 500
        if request.args['state'] != session['auth_state']:
            return "attack detected :)", 500

        # with this authorization code we can fetch an access token
        url = f"{settings.OPENID_URL}/token"
        data = {
            "grant_type": "authorization_code",
            "code": request.args["code"],
            "redirect_uri": settings.OPENID_REDIRECT_URI,
            "client_id": settings.OPENID_CLIENT_ID,
            "client_secret": settings.OPENID_CLIENT_SECRET,
            "state": request.args['state']
        }
        try:
            resp = requests.post(url, data=data)
            resp.raise_for_status()
        except:
            return "something went wrong :( #1", 500

        data = resp.json()
        assert "access_token" in data
        access_token = data['access_token']

        # fetch user information with the access token
        url = f"{settings.OPENID_URL}/userinfo"

        try:
            resp = requests.post(url, headers={"Authorization": f"Bearer {access_token}"})
            resp.raise_for_status()
            user_profile = resp.json()
        except:
            return "something went wrong :( #2", 500

        username = user_profile.get("preferred_username")
        sub = user_profile.get("sub")
        if not username:
            return "something went wrong :( #3", 500

        sub_uuid = uuid.UUID(sub)
        user = User.query.filter_by(username=username).first()
        if user:
            if not user.uuid:
                user.uuid = sub_uuid
                db.session.commit()
                db.session.flush()
        else:
            user = User.add(username=username,
                            password=None, email=None, uuid=sub_uuid)
        login_user(user)
        response = redirect(request.args.get('next') or url_for('index'))
        response.headers['X-Set-Cookie'] = True
        return response


@app.route('/login', methods=['GET', 'POST'])
@endpoint.api(
    parameter('username', type=str, location='form', required=False),
    parameter('password', type=str, location='form', required=False)
)
def login(username, password):
    if settings.OPENID_ENABLED:
        state = uuid.uuid4().hex
        session['auth_state'] = state

        url = f"{settings.OPENID_URL}/auth?" \
              f"client_id={settings.OPENID_CLIENT_ID}&" \
              f"redirect_uri={settings.OPENID_REDIRECT_URI}&" \
              f"response_type=code&" \
              f"state={state}"

        return redirect(url)

    if not username or not password:
        flash('Enter username/password pl0x')
        return make_response(render_template('login.html'))

    if request.method == 'GET':
        return make_response(render_template('login.html'))

    from funding.factory import bcrypt
    user = User.query.filter_by(username=username).first()
    if user is None or not bcrypt.check_password_hash(user.password, password):
        flash('Username or Password is invalid', 'error')
        return make_response(render_template('login.html'))

    login_user(user)
    response = redirect(request.args.get('next') or url_for('index'))
    response.headers['X-Set-Cookie'] = True
    return response


@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    response = redirect(request.args.get('next') or url_for('login'))
    response.headers['X-Set-Cookie'] = True
    return response


@app.route('/static/<path:path>')
def static_route(path):
    return send_from_directory('static', path)
