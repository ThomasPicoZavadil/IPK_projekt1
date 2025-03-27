# Compiler to use
CXX := g++

# Compiler flags
# -std=c++20: Use C++20 standard
# -Wall: Enable all warnings
# -Wextra: Enable extra warnings
# -Wpedantic: Enforce strict compliance with the standard
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic

# Linker flags (currently empty, but can be used for libraries)
LDFLAGS := 

# Source files
SRCS := ipk-l4-scan.cpp tcpscan.cpp udpscan.cpp

# Object files (derived from source files)
OBJS := $(SRCS:.cpp=.o)

# Target executable name
TARGET := ipk-l4-scan

# Default target: Build the executable
all: $(TARGET)

# Rule to link object files into the final executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to clean up generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Declare phony targets (targets that are not actual files)
.PHONY: all clean
