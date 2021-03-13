import re

import requests
from flask import jsonify, send_from_directory, Response
from flask_yoloapi import endpoint, parameter

from funding.bin.utils import get_ip
from funding.bin.qr import QrCodeGenerator
from funding.factory import app, cache
from funding.orm import Proposal


@app.route('/api/1/proposals')
@endpoint.api(
    parameter('status', type=int, location='args', default=1),
    parameter('cat', type=str, location='args'),
    parameter('limit', type=int, location='args', default=20),
    parameter('offset', type=int, location='args', default=0)
)
def api_proposals_get(status, cat, limit, offset):
    try:
        proposals = Proposal.find_by_args(status=status, cat=cat, limit=limit, offset=offset)
    except Exception as ex:
        print(ex)
        return 'error', 500
    return [p.json for p in proposals]


@app.route('/api/1/qr')
@endpoint.api(
    parameter('address', type=str, location='args', required=True)
)
def api_qr_generate(address):
    """
    Generate a QR image. Subject to IP throttling.
    :param address: valid receiving address
    :return:
    """
    from funding.factory import cache

    qr = QrCodeGenerator()
    if not qr.exists(address):
        # create a new QR code
        ip = get_ip()
        cache_key = 'qr_ip_%s' % ip
        hit = cache.get(cache_key)

        if hit and ip not in ['127.0.0.1', 'localhost']:
            return Response('Wait a bit before generating a new QR', 403)

        throttling_seconds = 3
        cache.set(cache_key, {'fundingwrkz': 'kek'}, throttling_seconds)

        created = qr.create(address)
        if not created:
            raise Exception('Could not create QR code')

    return send_from_directory('static/qr', '%s.png' % address)

