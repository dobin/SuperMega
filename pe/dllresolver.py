import sys
import ctypes
import os

from pe.superpe import SuperPe


class DllResolve():
    def __init__(self, dllname, cdll_res, path_res):
        self.dllname = dllname
        self.cdll_res = cdll_res
        self.path_res = path_res


def all_dll_exist(superpe):
    for dll_name in superpe.get_iat_entries():
        if not check_dll_availability(dll_name):
            return False
    return True

def unresolved_dlls(superpe):
    res = []
    for dll_name in superpe.get_iat_entries():
        if not check_dll_availability(dll_name):
            res.append(dll_name)
    return res


def resolve_dlls(superpe):
    res = []
    for dll_name in superpe.get_iat_entries():
        res.append(resolve_dll(dll_name))
    return res


def resolve_dll(dllname):
    cdll_res = check_dll_availability(dllname)
    path_res = search_for_dll(dllname)
    return DllResolve(dllname, cdll_res, path_res)


def check_dll_availability(dll_name):
    try:
        _ = ctypes.CDLL(dll_name)
        return True
    except OSError:
        return False


def search_for_dll(dll_name):
    paths = [
        os.getcwd(),  # Current directory
        os.environ.get('SYSTEMROOT', '') + '\\System32',  # System directory
        os.environ.get('SYSTEMROOT', ''),  # Windows directory
    ] + os.environ.get('PATH', '').split(';')  # PATH directories

    for path in paths:
        full_path = os.path.join(path, dll_name)
        if os.path.exists(full_path):
            return full_path
    return None
