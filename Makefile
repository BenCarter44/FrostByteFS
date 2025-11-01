# Target executable name
TARGET = frost

# Compiler
CC = gcc

# Compiler and Linker flags (combined)
# -Wall: Enable all warnings
# -Iheader: Look in 'header' directory for .h files
# `pkg-config...`: Get all FUSE flags and libraries
CFLAGS = -Wall -Iinclude `pkg-config fuse3 --cflags --libs`

# Source files
SRCS = src/main.c src/callbacks.c


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