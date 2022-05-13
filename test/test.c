#include<stdio.h>

int dofunc(){
	char buf[8]={};
	write(1,"input:",6);
	read(0,buf,0x100);
	return 0;
}

int main(){
	dofunc();
	return 0;
}