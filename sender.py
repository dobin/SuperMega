import requests as req
import logging
import brotli
import os
import time
import shutil

from config import config


def scannerDetectsBytes(data: bytes, filename: str, useBrotli=True, verify=False):
    params = { 'filename': filename, 'brotli': useBrotli, 'verify': verify }
    if useBrotli:
        scanData = brotli.compress(data)
    else:
        scanData = data

    timeStart = time.time()
    print("Send to exec/exe: {}".format(params))
    res = req.post("{}/exec/exe".format(config.get("avred_server")), params=params, data=scanData, timeout=10)
    jsonRes = res.json()
    print("Response: {}".format(jsonRes))
    scanTime = round(time.time() - timeStart, 3)

    # basically internal server error, e.g. AMSI not working
    if res.status_code != 200:
        logging.error("Error Code {}: {}".format(res.status_code, res.text))
        raise Exception("Server error, aborting")
    
    return jsonRes


def main():
    with open("data/exes/7z-verify.exe", "rb") as f:
        data = f.read()
    res = scannerDetectsBytes(data, "test.exe")
    print("Answer: {}".format(res))
