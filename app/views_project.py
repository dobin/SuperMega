from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from threading import Thread
import os
import logging
from typing import List, Tuple
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
import subprocess
from ansi2html import Ansi2HTMLConverter

from observer import observer
from config import config
from model.settings import Settings
from model.defs import *
from supermega import start
from app.storage import storage, WebProject
from sender import scannerDetectsBytes
from phases.injector import verify_injected_exe
from helper import run_process_checkret, run_exe
from model.project import prepare_project
from pe.superpe import SuperPe 
from model.exehost import ExeHost
import pe.dllresolver


logger = logging.getLogger("ViewsProjects")

views_project = Blueprint('views_project', __name__)

conv = Ansi2HTMLConverter()
config.load()
thread_running = False


@views_project.route("/projects")
def projects_route():
    projects = storage.get_projects()
    return render_template('projects.html', projects=projects)


@views_project.route("/project/<name>")
def project(name):
    project = storage.get_project(name)
    if project == None:
        return redirect("/projects", code=302)
    
    exe_path = project.settings.inject_exe_out
    is_built = False
    if os.path.exists(exe_path):
        is_built = True

    exports = []
    is_64 = False
    is_dotnet = False
    code_sect_size = 0
    data_sect_size = 0
    data_sect_largest_gap_size = 0
    payload_len = 0
    unresolved_dlls = []
    has_remote = False

    if config.get("avred_server") != "":
        has_remote = True

    # when we select a shellcode
    if project.settings.payload_path != "":
        payload_len = os.path.getsize(project.settings.payload_path)

    # when we selected an input file
    if project.settings.inject_exe_in != "" and os.path.exists(project.settings.inject_exe_in):
        superpe = SuperPe(project.settings.inject_exe_in)
        #if not superpe.is_64():
        #    # return 500
        #    return "Error: Binary {} is not 64bit".format(project.settings.inject_exe_in), 500

        is_64 = superpe.is_64()
        is_dotnet = superpe.is_dotnet()
        if superpe.is_dll():
            exports = superpe.get_exports_full()
        code_sect_size = superpe.get_code_section().Misc_VirtualSize
        if superpe.get_section_by_name(".rdata") != None:
            data_sect_size = superpe.get_section_by_name(".rdata").virt_size
        else:
            logger.warn("No .rdata section found in {}".format(project.settings.inject_exe_in))
        
        has_rodata_section = superpe.has_rodata_section()
        if has_rodata_section:
            exehost = ExeHost(project.settings.inject_exe_in)
            exehost.init()
            data_sect_largest_gap_size = exehost.get_rdata_relocmanager().find_largest_gap()
        unresolved_dlls = pe.dllresolver.unresolved_dlls(superpe)


    project_dir = os.path.dirname(os.path.abspath(project.settings.inject_exe_out))
    log_files = get_logfiles(project.settings.main_dir)

    exes = list_files_and_sizes(PATH_EXES, prepend=PATH_EXES)
    exes += list_files_and_sizes(PATH_EXES_MORE, prepend=PATH_EXES_MORE)
    #for file in 
    #    exes.append(PATH_EXES + file)
    #for file in os.listdir(PATH_EXES_MORE):
    #    exes.append(PATH_EXES_MORE + file)

    shellcodes = list_files_and_sizes(PATH_SHELLCODES)

    function_invoke_styles = [(color.name, color.value) for color in FunctionInvokeStyle]
    decoderstyles = [(color.name, color.value) for color in DecoderStyle]
    carrier_invoke_styles = [(color.name, color.value) for color in CarrierInvokeStyle]

    return render_template('project.html', 
        project_name = name,
        project=project, 
        is_built=is_built,
        project_dir=project_dir,
        
        exes=exes,
        shellcodes=shellcodes,
        function_invoke_styles=function_invoke_styles,
        decoderstyles=decoderstyles,
        carrier_invoke_styles=carrier_invoke_styles,
        exports=exports,

        log_files=log_files,
        is_64=is_64,
        is_dotnet=is_dotnet,
        code_sect_size=code_sect_size,
        data_sect_size=data_sect_size,
        data_sect_largest_gap_size=data_sect_largest_gap_size,
        payload_len=payload_len,
        unresolved_dlls=unresolved_dlls,
        has_rodata_section=has_rodata_section,

        has_remote=has_remote,
    )

def list_files_and_sizes(directory, prepend=""):
    # List all files in the directory and get their sizes
    files_and_sizes = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            size = os.path.getsize(filepath)
            files_and_sizes.append({
                "filename": prepend + filename,
                "size": size,
            })
    return files_and_sizes

@views_project.route("/project_add", methods=['POST', 'GET'])
def add_project():
    if request.method == 'POST':
        settings = Settings()

        project_name = request.form['project_name']
        comment = request.form['comment']

        # new project?
        if storage.get_project(project_name) == None:
            # add new project
            project = WebProject(project_name, settings)
            project.comment = comment
            storage.add_project(project)
        
        # update project
        else:
            settings.payload_path = PATH_SHELLCODES + request.form['shellcode']
            if request.form['shellcode'] == "createfile.bin":
                settings.verify = True
                settings.try_start_final_infected_exe = False
            else:
                settings.cleanup_files_on_exit = False

            if 'dllfunc' in request.form:
                settings.dllfunc = request.form['dllfunc']

            settings.inject_exe_in = request.form['exe']
            settings.inject_exe_out = request.form['exe'].replace(".exe", ".infected.exe")

            source_style = request.form['source_style']
            settings.source_style = FunctionInvokeStyle[source_style]

            carrier_invoke_style = request.form['carrier_invoke_style']
            settings.carrier_invoke_style = CarrierInvokeStyle[carrier_invoke_style]

            decoder_style = request.form['decoder_style']
            settings.decoder_style = DecoderStyle[decoder_style]

            # overwrite project
            project = storage.get_project(project_name)
            project.settings = settings
            project.comment = comment
            storage.save_project(project)

        return redirect("/project/{}".format(project_name), code=302)
    
    else: # GET
        return render_template('project_add_get.html')


def supermega_thread(settings: Settings):
    global thread_running
    start(settings)
    thread_running = False


@views_project.route("/project/<project_name>/build", methods=['POST', 'GET'])
def build_project(project_name):
    global thread_running

    project = storage.get_project(project_name)

    #if project.settings.inject_exe_in.endswith(".dll"):
    #    if project.settings.dllfunc == "":
    #        logger.error("DLL injection requires a DLL function name")
    #        return redirect("/project/{}".format(project_name), code=302)

    project.settings.try_start_final_infected_exe = False
    prepare_project(project_name, project.settings)
    thread = Thread(target=supermega_thread, args=(project.settings, ))
    thread.start()
    thread_running = True

    return redirect("/project/{}/status".format(project_name), code=302)


@views_project.route("/project/<project_name>/status")
def status_project(project_name):
    global thread_running
    if thread_running:
        return render_template('status_project.html', 
            project_name=project_name,
            logdata = "\n".join(observer.get_logs()))
    else:
        return redirect("/project/{}".format(project_name), code=302)


@views_project.route("/project/<project_name>/exec", methods=['POST', 'GET'])
def start_project(project_name):
    project = storage.get_project(project_name)
    if project == None:
        return redirect("/", code=302)

    remote = False
    remote_arg = request.args.get('remote')
    if remote_arg == "true":
        remote = True

    no_exec = False
    no_exec_arg = request.args.get('no_exec')
    if no_exec_arg == "true":
        no_exec = True

    logger.info("--[ Exec project: {} remote: {} no_exec: {}".format(project_name, remote, no_exec))

    if remote:
        logger.info("--[ Exec {} on server {}".format(project.settings.inject_exe_out, config.get("avred_server")))
        with open(project.settings.inject_exe_out, "rb") as f:
            data = f.read()
        filename = os.path.basename(project.settings.inject_exe_out)
        try:
            scannerDetectsBytes(data, 
                                filename, 
                                useBrotli=True, 
                                verify=project.settings.verify,
                                no_exec=no_exec)
        except Exception as e:
            logger.error(f'Error scanning: {e}')
            return jsonify({
				"exception": str(e)
			}), 500
    else:
        # Start/verify it at the end
        if project.settings.verify:
            logger.info("--[ Verify infected exe")
            exit_code = verify_injected_exe(project.settings.inject_exe_out)
        elif no_exec == False:
            run_exe(project.settings.inject_exe_out, dllfunc=project.settings.dllfunc, check=False)
        elif no_exec == True:
            dirname = os.path.dirname(os.path.abspath(project.settings.inject_exe_out))
            logger.info("--[ Open folder: {}".format(dirname))
            subprocess.run(['explorer', dirname])

    return redirect("/project/{}".format(project_name), code=302)


def get_logfiles(directory):
    log_files = []
    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir(f"{directory}/"):
        if file.startswith("."):
            continue
        if not file.startswith("log-"):
            continue
        if file.endswith(".bin"):
            continue

        with open(os.path.join(f"{directory}/", file), "r") as f:
            data = f.read()
            if 'main_c' in file:
                data = highlight(data, CLexer(), HtmlFormatter(full=False))
            elif '_asm_' in file:
                # handle special cases
                if '_orig' in file:
                    asm_a = data
                if '_updated' in file:
                    asm_b = data
                data = highlight(data, NasmLexer(), HtmlFormatter(full=False))
            elif '.ascii' in file:
                data = conv.convert(data, full=False)
            elif '.txt' in file:
                continue # skip it 
            elif '.hex' in file:
                continue # skip it 
                #data = escape(data)
                #data = highlight(data, HexdumpLexer(), HtmlFormatter(full=False))
            elif '.log' in file:
                data = conv.convert(data, full=False)
            else:
                data = escape(data)

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
                    "name": "Summary: ASM Diff".format(),
                    "id": str(id),
                    "content": diff_l,
                }
                log_files.append(entry)
                id += 1
                #asm_a = ""
                asm_b = ""
    return log_files