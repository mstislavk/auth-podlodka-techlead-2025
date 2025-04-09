import os
import requests
import jwt

from urllib import parse
from flask import Flask, request, abort
from pprint import pprint


app = Flask(__name__)


@app.route("/")
def pdp():
    """Отдаёт 200 или 403 код"""
    # Анонимные запросы запрещаем
    if not get_token(request.headers):
        return forbidden()

    if is_authorized(request):
        return allowed()

    return forbidden()


def is_authorized(request):
    if not is_token_valid(get_token(request.headers)):
        return False

    method = get_method(request)
    path = get_path(request)
    params = get_params(request)
    payload = get_payload(get_token(request.headers))
    pprint(request.headers)

    print("Method: " + method)
    print("Path: " + path)
    print("Params: " + str(params))
    print("Payload: " + str(payload))

    # Список мед. карт отфильтрованных по региону доктора
    if (
            method == "GET" and
            path == "/api/data/references/medcards/items/" and
            payload["region"] == params["medcard-region"]
    ):
        return True

    return False


# ======== Вспомогательные функции


def get_payload(token):
    return jwt.decode(token, options={"verify_signature": False})


def get_params(request):
    return parse.parse_qs(parse.urlparse(request.headers["X-Forwarded-Uri"]).query)


def get_method(request):
    return request.headers["X-Forwarded-Method"]


def get_path(request):
    return parse.urlparse(request.headers["X-Forwarded-Uri"]).path


def is_token_valid(token):
    # TODO: реализуйте валидацию токена самостоятельно
    # с помощью публичного ключа, которые добавите в переменную окружения,
    # настройки или получая их по URL с помощью PyJWKClient
    return True


def get_token(headers):
    header = headers.get("Authorization")
    if header:
        return header.split()[-1]


def forbidden():
    """Возврат HTTP-ответа с 403 кодом"""
    return abort(403)


def allowed():
    """Возврат HTTP-ответа с 200 кодом"""
    return ""
