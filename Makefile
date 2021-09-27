tcp_uds_gwm: tcp_uds_gwm.o
	gcc -o tcp_uds_gwm tcp_uds_gwm.o

tcp_uds_gwm.o: tcp_uds_gwm.c
	gcc -c tcp_uds_gwm.c

clean:
	rm tcp_uds_gwm.o
	rm tcp_uds_gwm
