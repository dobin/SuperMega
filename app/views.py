from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple

from model.defs import *

views = Blueprint('views', __name__)
logger = logging.getLogger("Views")


@views.route("/")
def index():
    return render_template('index.html')
