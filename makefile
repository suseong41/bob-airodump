CXX = g++
CXXFLAGS = -std=c++20
LDLIBS=-lpcap

all: airodump

airodump: main.o beacon.o radiotap.o 802_11.o
	$(CXX) main.o beacon.o radiotap.o 802_11.o $(LDLIBS) -o airodump

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

beacon.o: beacon.cpp beacon.h
	$(CXX) $(CXXFLAGS) -c beacon.cpp -o beacon.o

radiotap.o: radiotap.cpp radiotap.h
	$(CXX) $(CXXFLAGS) -c radiotap.cpp -o radiotap.o   
	
802_11.o: 802_11.cpp 802_11.h
	$(CXX) $(CXXFLAGS) -c 802_11.cpp -o 802_11.o

clean:
	rm -f airodump *.o