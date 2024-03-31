from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from threading import Thread
import os
import logging
from typing import List, Tuple
from datetime import datetime

from observer import observer
from model.defs import *
from supermega import start
from phases.compiler import compile_dev
from phases.assembler import asm_to_shellcode
from helper import clean_tmp_files

views_shcdev = Blueprint('views_shcdev', __name__)
logger = logging.getLogger("ViewsShcdev")

@views_shcdev.route("/shcdev")
def devs_route():
    data = []
    for filename in os.listdir(PATH_PAYLOAD):
        file_path = PATH_PAYLOAD + filename
        creation_time = os.path.getctime(file_path)
        readable_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
        data.append({
            "name": filename,
            "date": readable_time,
        })
    return render_template('devs.html', data=data)


@views_shcdev.route("/shcdev/<name>")
def dev_route(name):
    data = []
    log = ""
    path = PATH_PAYLOAD + name
    for filename in os.listdir(path):
        filepath = path + "/" + filename
        
        creation_time = os.path.getmtime(filepath)
        readable_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
        
        info = ""
        if filename.endswith(".asm"):
            info = "text assembly (cleaned, from compiled .c)"
        elif filename.endswith(".bin"):
            info = "generated shellcode (from .exe)"
        elif filename.endswith(".c"):
            info = "input C code"
        elif filename.endswith(".exe"):
            info = "temporary shellcode holder (from .c)"
        elif filename.endswith("cmdoutput.log"):
            info = "command output"
            with open(path + "/" + filename, "r") as f:
                log += f.read() + "\n-----------------------------------\n"
        elif filename.endswith("supermega.log"):
            info = "supermega logging output"
            with open(path + "/" + filename, "r") as f:
                log += f.read()

        data.append({
            "name": filename,
            "date": readable_time,
            "info": info,
        })

    return render_template('dev.html', 
        name=name, files=data, log=log)


@views_shcdev.route("/shcdev/<name>/build")
def dev_build_route(name):

    c_in = PATH_PAYLOAD + "{}/main.c".format(name)
    asm_out = PATH_PAYLOAD + "{}/main.asm".format(name)
    build_exe = PATH_PAYLOAD + "{}/main.exe".format(name)
    shellcode_out = PATH_PAYLOAD + "{}/main.bin".format(name)

    compile_dev(c_in, asm_out)
    asm_to_shellcode(asm_out, build_exe, shellcode_out)
    observer.write_logs(PATH_PAYLOAD + "{}/".format(name))
    clean_tmp_files()
    return redirect("/shcdev/{}".format(name), code=302)
