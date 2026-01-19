CXX = g++
CXXFLAGS = -std=c++20
LDLIBS=-lpcap

all: airodump

airodump: main.o wireless.o
	$(CXX) main.o $(LDLIBS) -o airodump

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

wireless.o: wireless.cpp

clean:
	rm -f airodump *.o