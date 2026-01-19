CXX = g++
LDLIBS=-lpcap

all: airodump

airodump: main.o
	$(CXX) main.o $(LDLIBS) -o airodump

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

clean:
	rm -f airodump *.o