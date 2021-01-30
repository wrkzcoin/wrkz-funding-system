from datetime import datetime, date

import requests
from flask import request

import settings
from funding.factory import cache


def json_encoder(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


class Summary:
    @staticmethod
    @cache.cached(timeout=600, key_prefix="funding_stats")
    def fetch_stats():
        from funding.factory import db
        from funding.orm import Proposal, User

        data = {}
        categories = settings.FUNDING_CATEGORIES
        statuses = settings.FUNDING_STATUSES.keys()

        for cat in categories:
            q = db.session.query(Proposal)
            q = q.filter(Proposal.category == cat)
            res = q.count()
            data.setdefault('cats', {})
            data['cats'][cat] = res

        for status in statuses:
            q = db.session.query(Proposal)
            q = q.filter(Proposal.status == status)
            res = q.count()
            data.setdefault('statuses', {})
            data['statuses'][status] = res

        data.setdefault('users', {})
        data['users']['count'] = db.session.query(User.id).count()
        return data


def coin_to_usd(amt: float):
    # TODO: use live price later
    per_coin = 0.0000001700
    try:
        return round(amt * per_coin, 4)
    except:
        pass


def get_ip():
    return request.headers.get('X-Forwarded-For') or request.remote_addr
