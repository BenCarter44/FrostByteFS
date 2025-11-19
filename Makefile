# Target executable name
TARGET = frost

# Compiler
CC = gcc

# Compiler and Linker flags (combined)
# -Wall: Enable all warnings
# -Iheader: Look in 'header' directory for .h files
# `pkg-config...`: Get all FUSE flags and libraries
CFLAGS = -Wall -Iinclude `pkg-config fuse3 --cflags --libs` -Wl,-rpath=/usr/local/lib64 -lpthread

# Source files
SRCS = src/main.c src/callbacks.c src/inode.c src/allocator.c src/rawdisk.c src/error.c


# --- Rules ---

# The 'all' rule is the default goal
.PHONY: all
all: $(TARGET)

# Rule to build the executable
# Compiles and links all source files in one step
$(TARGET): $(SRCS)
	@echo "Compiling and linking $(TARGET)..."
	$(CC) -o $(TARGET) $(SRCS) $(CFLAGS)
	@echo "$(TARGET) build complete."

# 'clean' rule to remove the built executable
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)
	@echo "Clean complete."


# Unit test target
TEST_TARGET = test_inode
TEST_SRCS = tests/test_inode.c src/inode.c src/allocator.c src/rawdisk.c

.PHONY: test
test: $(TEST_TARGET)
	@echo "Running inode layer unit tests..."
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS)
	@echo "Compiling unit tests..."
	$(CC) -Wall -g -Iinclude -lpthread `pkg-config fuse3 --cflags --libs` -o $(TEST_TARGET) $(TEST_SRCS)
	@echo "Test build complete."


