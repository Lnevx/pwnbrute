from random import randint

from pwn import process

import pwnbrute


def main():
    io = process('sh')

    # Some heavy logic
    io.sendline(b'echo foo')
    for _ in range(10):
        io.sendlineafter(b'foo', b'sleep 0.1; echo foo')

    # Maybe exploit timeouted...
    if randint(0, 1):
        io.sendline(b'sleep 60; echo bar')
        io.recvuntil(b'bar')

    # Probalistic part (for example, the brute force of 0,5 bytes ASLR with 2^-4 %)
    if randint(1, 1 << 4) != 1:
        raise EOFError('Probalistic part not passed...')

    # Do some stuff after (for example, print flag)
    io.sendline(b'echo ctf{test}')

    # Return console to exploit and maybe do other stuff...
    pwnbrute.success()
    io.interactive()


if __name__ == '__main__':
    # Start bruteforce
    pwnbrute.brute(main, workers=16, timeout=3, save_timeouts=True)
