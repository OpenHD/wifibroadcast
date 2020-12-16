
# bring in the helper from the parent / src / HelperSources File
# kinda dirty (fixme but how)
HELPER_DIR := ../../src/HelperSources/

test : test.cpp
	g++ -std=c++17 test.cpp UDPReceiver.cpp UDPSender.cpp -o test -lpthread -I $(HELPER_DIR)

clean:
	rm -rf test