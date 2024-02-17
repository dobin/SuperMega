from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template, send_file, make_response, session
from werkzeug.utils import secure_filename
import os
import logging
import io
from typing import List, Tuple
from datetime import date
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer
from pygments.formatters import HtmlFormatter
import difflib

views = Blueprint('views', __name__)


@views.route("/")
def index():
    return render_template('index.html')


@views.route("/project")
def project():
    # read the content of all files in logs
    log_files = []

    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir("logs"):
        if file.endswith(".txt"):
            print("Handle: ", file)

            with open(os.path.join("logs", file), "r") as f:
                data = f.read()

                if 'main_c' in file:
                    data = highlight(data, CLexer(), HtmlFormatter(full=False))
                elif '_asm' in file:
                    # handle special cases
                    if '_orig' in file:
                        asm_a = data
                    if '_cleanup' in file:
                        asm_b = data


                    data = highlight(data, NasmLexer(), HtmlFormatter(full=False))

                entry = {
                    "name": file,
                    "id": str(id),
                    "content": data,
                }
                log_files.append(entry)
                id += 1

                # more
                if asm_a != "" and asm_b != "":
                    # do the diff from the content of the two files
                    a = asm_a.splitlines()
                    b = asm_b.splitlines()
                    diff_generator = difflib.unified_diff(a, b, lineterm='')
                    diff_string = '\n'.join(diff_generator)
                    diff_l = highlight(diff_string, DiffLexer(), HtmlFormatter(full=False))
                    entry = {
                        "name": "_asm_diff".format(),
                        "id": str(id),
                        "content": diff_l,
                    }
                    log_files.append(entry)
                    id += 1
                    asm_a = ""
                    asm_b = ""


    return render_template('project.html', 
        log_files=log_files
    )
