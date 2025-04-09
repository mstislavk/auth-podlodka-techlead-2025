import os
import re
import traceback

import requests
import json
import jwt
import jsonschema

from pprint import pprint
from urllib import parse
from flask import Flask, request, abort


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

    context = {}
    context["method"] = get_method(request)
    context["path"] = get_path(request)
    context["params"] = get_params(request)
    context["token"] = get_payload(get_token(request.headers))
    pprint(context)

    schema = substitute(open("policies/medcards.json").read(), context)
    pprint(schema)
    schema = json.loads(schema)
    try:
        jsonschema.validate(instance=context, schema=schema)
        return True
    except (jsonschema.exceptions.ValidationError, jsonschema.exceptions.SchemaError):
        traceback.print_exc()

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


def substitute(template, context):
    """Замена ${context["params"]["test"]} на значение"""
    variables = re.findall(r"\$\{([^\}]*)\}", template)
    for v in variables:
        extracted_data = context.copy()
        for k in re.findall(r'\["([^"]*)"\]', v):
            try:
                extracted_data = extracted_data.get(k)
                if not extracted_data:
                    break
            except AttributeError:
                break
        template = template.replace(
            "${" + v + "}", json.dumps(extracted_data)
        )
    return template
