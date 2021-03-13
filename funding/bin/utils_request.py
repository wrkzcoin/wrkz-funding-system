from flask import request
import settings
from funding.bin.utils import Summary
from funding.factory import app, db
from funding.orm import User, Comment


@app.context_processor
def templating():
    from flask_login import current_user
    recent_comments = db.session.query(Comment).filter(Comment.automated == False).order_by(Comment.date_added.desc()).limit(8).all()
    summary_data = Summary.fetch_stats()
    newest_users = db.session.query(User).filter(User.admin == False).order_by(User.registered_on.desc()).limit(5).all()
    return dict(logged_in=current_user.is_authenticated,
                current_user=current_user,
                funding_categories=settings.FUNDING_CATEGORIES,
                funding_statuses=settings.FUNDING_STATUSES,
                summary_data=summary_data,
                recent_comments=recent_comments,
                newest_users=newest_users)


@app.before_request
def before_request():
    pass


@app.after_request
def after_request(res):
    res.headers.add('Accept-Ranges', 'bytes')

    if request.full_path.startswith('/api/'):
        res.headers.add('Access-Control-Allow-Origin', '*')

    if settings.DEBUG:
        res.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        res.headers['Pragma'] = 'no-cache'
        res.headers['Expires'] = '0'
        res.headers['Cache-Control'] = 'public, max-age=0'
    return res


@app.errorhandler(404)
def error(err):
    return 'Error', 404
