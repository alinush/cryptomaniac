all:
	gcc cryptomaniac.c -lcrypto -std=gnu99 -o cryptomaniac
clean:
	rm cryptomaniac
