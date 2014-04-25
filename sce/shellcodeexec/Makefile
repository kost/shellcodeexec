CC ?= gcc
STRIP ?= strip
# STRIPFLAGS += -sx
CFLAGS += -Wall -Os 
# CFLAGS += -DDEBUG=1
# CFLAGS += -static
CFLAGS64 += -fPIC 
OUT ?= shellcodeexec

32:
	$(CC) shellcodeexec.c -o $(OUT) $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) $(OUT)

64:
	$(CC) shellcodeexec.c $(CFLAGS64) -o $(OUT) $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) $(OUT)
