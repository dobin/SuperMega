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

    # r2 cant really handle shellcode when not in files...
    with open(filename, "wb") as f:
        f.write(data)
    code_len = len(data)

    if code_len > 0x2000:
        ret['text'] = "Code too long for r2: {}".format(code_len)
        ret['color'] = "Code too long for r2: {}".format(code_len)
        return ret

    r2 = r2pipe.open(filename, flags=['-2'])
    r2.cmd('aaa')

    r2.cmd('e scr.color=0')
    ret['text'] = r2.cmd('pD {}'.format(code_len))
    ret['text'] = '\n'.join(ret['text'].splitlines())  # fix newlines

    r2.cmd('e scr.color=2')
    ret['color'] = r2.cmd('pD {}'.format(code_len))
    ret['color'] = '\n'.join(ret['color'].splitlines())  # fix newlines

    r2.quit()
    os.remove(filename)

    return ret