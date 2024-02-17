import r2pipe
import os

from defs import *
from helper import hexdump

def r2_disas(data: bytes):
    filename = "r2_data.bin"
    ret = {
        'text': None,
        'color': None,
        'hexdump': None,
    }

    ret["hexdump"] = hexdump(data)

    # fucking r2 cant handle shellcode when not in files...
    with open(filename, "wb") as f:
        f.write(data)

    r2 = r2pipe.open(filename)
    r2.cmd('aaa')

    r2.cmd('e scr.color=0')
    ret['text'] = r2.cmd('pd')
    ret['text'] = '\n'.join(ret['text'].splitlines())  # fix newlines

    r2.cmd('e scr.color=2')
    ret['color'] = r2.cmd('pd')
    ret['color'] = '\n'.join(ret['color'].splitlines())  # fix newlines

    r2.quit()
    os.remove(filename)

    return ret