from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple

from pe.superpe import SuperPe
from model.defs import *
from pe.dllresolver import resolve_dlls

views = Blueprint('views', __name__)
logger = logging.getLogger("Views")


@views.route("/")
def index():
    return render_template('index.html')


@views.route("/exes/<exe_name>")
def exe_view(exe_name):
    path = "{}/{}".format(PATH_EXES, exe_name)
    superpe = SuperPe(path)

    return render_template('exe.html', 
                           superpe=superpe, 
                           resolved_dlls=resolve_dlls(superpe),
                           iat=superpe.get_iat_entries(),
                           exports=superpe.get_exports_full(),
    )


@views.route("/exes")
def exes_view():
    exes = []
    for file in os.listdir(PATH_EXES):
        if not file.endswith(".dll") and not file.endswith(".exe"):
            continue
        if '.verify' in file or '.test' in file:
            continue

        superpe = SuperPe("{}/{}".format(PATH_EXES, file))

        e = {
            'name': file,
            #'exports': superpe.get_exports_full(),
            #'iat': superpe.get_iat_entries(),
            'sections': superpe.pe_sections,
        }
        exes.append(e)
        #break
    return render_template('exes.html', exes=exes)


@views.app_template_filter('hexint')
def hex_filter(s):
    return hex(s)

@views.app_template_filter('basename')
def basename(s):
    return os.path.basename(s)