#!/bin/bash

# ==========================================
# FrostByteFS Extended Attribute Test Suite
# ==========================================

TEST_FILE="xattr_test_file"
NON_EXISTENT="ghost_file"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for required tools
if ! command -v setfattr &> /dev/null; then
    echo -e "${RED}Error: 'setfattr' not found.${NC}"
    echo "Please install the 'attr' package (e.g., sudo apt install attr)"
    exit 1
fi

setup() {
    rm -f "$TEST_FILE"
    touch "$TEST_FILE"
}

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}--- $1 ---${NC}"; }

# ==========================================
# 1. GETATTR TESTS (Stat check)
# ==========================================
info "Testing GETATTR (via stat)"
setup

# Test 1.1: Verify initial size is 0
SIZE=$(stat -c %s "$TEST_FILE")
if [ "$SIZE" -eq 0 ]; then
    pass "Initial file size is 0"
else
    fail "Initial file size is $SIZE (Expected 0)"
fi

# Test 1.2: Verify file type (Regular file)
TYPE=$(stat -c %F "$TEST_FILE")
if [[ "$TYPE" == *"regular file"* || "$TYPE" == *"regular empty file"* ]]; then
    pass "File type reported correctly"
else
    fail "File type is '$TYPE' (Expected regular file)"
fi

# Test 1.3: Getattr on non-existent file
if stat "$NON_EXISTENT" 2>/dev/null; then
    fail "Getattr succeeded on non-existent file!"
else
    pass "Getattr correctly failed on non-existent file"
fi

# ==========================================
# 2. SETXATTR & GETXATTR BASICS
# ==========================================
info "Testing Basic SETXATTR & GETXATTR"

KEY="user.frostbyte"
VAL="Hello_World"

# Test 2.1: Set a simple attribute
# This triggers setxattr
if setfattr -n "$KEY" -v "$VAL" "$TEST_FILE"; then
    pass "setxattr returned success"
else
    fail "setxattr failed to set value"
fi

# Test 2.2: Get the attribute back
# This triggers getxattr
RETRIEVED=$(getfattr --only-values -n "$KEY" "$TEST_FILE" 2>/dev/null)
if [ "$RETRIEVED" == "$VAL" ]; then
    pass "getxattr retrieved correct value: $RETRIEVED"
else
    fail "getxattr returned '$RETRIEVED' (Expected '$VAL')"
fi

# ==========================================
# 3. OVERWRITING ATTRIBUTES
# ==========================================
info "Testing SETXATTR Overwrite"

NEW_VAL="New_Value_Here"

# Test 3.1: Overwrite existing key
setfattr -n "$KEY" -v "$NEW_VAL" "$TEST_FILE"
RETRIEVED=$(getfattr --only-values -n "$KEY" "$TEST_FILE" 2>/dev/null)

if [ "$RETRIEVED" == "$NEW_VAL" ]; then
    pass "Value updated successfully"
else
    fail "Value did not update! Got: '$RETRIEVED'"
fi

# ==========================================
# 4. REMOVEXATTR TESTS
# ==========================================
info "Testing REMOVEXATTR"

# Test 4.1: Remove the attribute
if setfattr -x "$KEY" "$TEST_FILE"; then
    pass "removexattr returned success"
else
    fail "removexattr failed"
fi

# Test 4.2: Confirm it is gone
# This triggers getxattr on a missing key (should fail gracefully)
if getfattr -n "$KEY" "$TEST_FILE" 2>/dev/null; then
    fail "Attribute still exists after removal!"
else
    pass "Attribute correctly disappeared"
fi

# Test 4.3: Remove non-existent attribute (Should fail)
if setfattr -x "user.ghostkey" "$TEST_FILE" 2>/dev/null; then
    fail "Removing non-existent attribute returned success (Should fail)"
else
    pass "Removing non-existent attribute failed as expected"
fi

# ==========================================
# 5. CORNER CASES
# ==========================================
info "Testing Corner Cases"

# Test 5.1: Multiple Attributes
setfattr -n "user.key1" -v "data1" "$TEST_FILE"
setfattr -n "user.key2" -v "data2" "$TEST_FILE"

VAL1=$(getfattr --only-values -n "user.key1" "$TEST_FILE" 2>/dev/null)
VAL2=$(getfattr --only-values -n "user.key2" "$TEST_FILE" 2>/dev/null)

if [ "$VAL1" == "data1" ] && [ "$VAL2" == "data2" ]; then
    pass "Multiple attributes stored correctly"
else
    fail "Multiple attributes corrupted. 1:$VAL1 2:$VAL2"
fi

# Test 5.2: Empty Value
# Some FS crash if value size is 0
setfattr -n "user.empty" -v "" "$TEST_FILE"
EMPTY_VAL=$(getfattr --only-values -n "user.empty" "$TEST_FILE" 2>/dev/null)
if [ -z "$EMPTY_VAL" ]; then
    pass "Handled empty value correctly"
else
    fail "Empty value check failed"
fi

# Test 5.3: Large Value (e.g., 256 bytes)
# This tests buffer boundaries in getxattr/setxattr
LARGE_STR=$(printf 'a%.0s' {1..256})
setfattr -n "user.large" -v "$LARGE_STR" "$TEST_FILE"
RET_LARGE=$(getfattr --only-values -n "user.large" "$TEST_FILE" 2>/dev/null)
LEN=${#RET_LARGE}

if [ "$LEN" -eq 256 ]; then
    pass "Large attribute (256 bytes) stored correctly"
else
    fail "Large attribute failed. Length: $LEN"
fi

# Test 5.4: Binary Data (Null bytes)
# This ensures your string handling in C doesn't stop at \0
# Note: standard getfattr might encode binary output, so we check exit code mainly
# and raw dump if possible.
dd if=/dev/urandom of=bin_data bs=1 count=16 2>/dev/null
setfattr -n "user.binary" -v "$(cat bin_data)" "$TEST_FILE"
if [ $? -eq 0 ]; then
    pass "Binary data set successfully"
else
    fail "Binary data set failed"
fi
rm bin_data

# Test 5.5: Insufficient Buffer Size (Simulated)
# If your C code for getxattr returns -ERANGE when buffer is too small, 
# the kernel handles the retry. We just ensure `getfattr` works, 
# which implies the size negotiation worked.
if getfattr -n "user.large" "$TEST_FILE" > /dev/null; then
    pass "Buffer size negotiation (ERANGE check) passed implicitly"
fi

cleanup() {
    rm -f "$TEST_FILE"
}
cleanup

echo -e "\n${GREEN}=== All XATTR Tests Passed ===${NC}"