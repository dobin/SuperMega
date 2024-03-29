from typing import List, Dict

from pe.r2helper import r2_disas


class Observer():
    """Central class to store all logs and files created during the build process"""

    def __init__(self):
        self.cmd_output = []        # output of external programs (cmdoutput.log)
        self.logs: List[str] = []   # internal log messages (supermega.log)
        self.files = []             # content of generated files 
        self.active = True


    def reset(self):
        self.cmd_output = []
        self.logs = []
        self.idx = 0


    def add_cmd_output(self, cmd_output):
        self.cmd_output.append(cmd_output)


    def get_cmd_output(self):
        return self.cmd_output


    def add_log(self, log: str):
        self.logs.append(log)


    def get_logs(self):
        return self.logs


    def add_text_file(self, name, data):
        self.files.append((name + ".txt", data))


    def add_code_file(self, name, data: bytes):
        ret = r2_disas(data)
        self.files.append((name + ".disas.ascii", ret['color']))
        #self.write_to_file(name + ".disas.txt", ret['text'])
        #self.write_to_file(name + ".disas.ascii", ret['color'])
        #self.write_to_file(name + ".hex", ret['hexdump'])
        #self.write_to_file_bin(name + ".bin", data)
 

observer = Observer()