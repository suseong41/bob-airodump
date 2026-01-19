LDLIBS=-lpcap

all: airodump

main.o: main.cpp

airodump: main.o

clean:
	rm -f airodump *.o