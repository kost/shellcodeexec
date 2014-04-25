CC ?= gcc
STRIP ?= strip
# STRIPFLAGS += -sx
CFLAGS += -Wall -Os 
# CFLAGS += -DDEBUG=1
# CFLAGS += -static
CFLAGS64 += -fPIC 

32:
	$(CC) shellcodeexec.c -o shellcodeexec $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) shellcodeexec

64:
	$(CC) shellcodeexec.c $(CFLAGS64) -o shellcodeexec $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) shellcodeexec
