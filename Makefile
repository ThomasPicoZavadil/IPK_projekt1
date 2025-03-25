CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic
LDFLAGS := 
SRCS := ipk-l4-scan.cpp tcpscan.cpp udpscan.cpp
OBJS := $(SRCS:.cpp=.o)
TARGET := ipk-l4-scan

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
