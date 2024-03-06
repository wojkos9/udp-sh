CC=gcc

all: dtls dtlsc

%: %.c
	$(CC) $< -o $@ -lssl -lcrypto

clean:
	rm dtls dtlsc