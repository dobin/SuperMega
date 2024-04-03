from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple

from pe.superpe import SuperPe
from model.defs import *

views = Blueprint('views', __name__)
logger = logging.getLogger("Views")


@views.route("/")
def index():
    return render_template('index.html')


@views.route("/exes/<exe_name>")
def exe_view(exe_name):
    path = "{}/{}".format(PATH_EXES, exe_name)
    superpe = SuperPe(path)
    return render_template('exe.html', superpe=superpe, iat=superpe.get_iat_entries())


@views.route("/exes")
def exes_view():
    exes = []
    for file in os.listdir(PATH_EXES):
        exes.append(file)
    return render_template('exes.html', exes=exes)

