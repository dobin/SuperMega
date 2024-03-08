import logging

from model.defs import *

log_messages = []


# Logging

# ANSI escape sequences for colors
class LogColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class CustomFormatter(logging.Formatter):
    #format = "%(asctime)s - %(name)-12s - [%(levelname)-8s] - %(message)s (%(filename)s:%(lineno)d)"
    format = "(%(filename)-12s) %(message)s"

    FORMATS = {
        logging.DEBUG: format,
        logging.INFO: format,
        logging.WARNING: LogColors.WARNING + format + LogColors.ENDC,
        logging.ERROR: LogColors.FAIL + format + LogColors.ENDC,
        logging.CRITICAL: LogColors.FAIL + LogColors.BOLD + format + LogColors.ENDC
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

class ListHandler(logging.Handler):
    def __init__(self, log_list):
        super().__init__()
        self.log_list = log_list

    def emit(self, record):
        # Format the log record and store it in the list
        log_entry = self.format(record)
        self.log_list.append(log_entry)


def writelog():
    # write log to file
    with open(f"{logs_dir}/supermega.log", "w") as f:
        for line in log_messages:
            f.write(line + "\n")

def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(CustomFormatter())

    list_handler = ListHandler(log_messages)
    list_handler.setLevel(logging.DEBUG)
    list_handler.setFormatter(CustomFormatter())

    root_logger.addHandler(ch)
    root_logger.addHandler(list_handler)

def clear_log():
    log_messages.clear()
