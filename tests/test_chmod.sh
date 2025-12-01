#!/bin/bash

# Configuration
TEST_FILE="frostbyte_test_file"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper function to check permissions
check_perm() {
    EXPECTED=$1
    # stat -c %a gets the octal permission (e.g., 755)
    ACTUAL=$(stat -c %a "$TEST_FILE")
    
    if [ "$ACTUAL" == "$EXPECTED" ]; then
        echo -e "${GREEN}[PASS]${NC} Mode is $ACTUAL (Expected $EXPECTED)"
    else
        echo -e "${RED}[FAIL]${NC} Mode is $ACTUAL (Expected $EXPECTED)"
        exit 1
    fi
}

echo -e "${BLUE}=== Starting FrostByteFS Chmod Tests ===${NC}"

# 1. Cleanup and Setup
rm -f "$TEST_FILE"
touch "$TEST_FILE"
echo "Created test file: $TEST_FILE"

# 2. Test Basic Octal Modes
echo -e "\n${BLUE}--- Testing Basic Octal Modes ---${NC}"

echo "Testing 777 (rwxrwxrwx)..."
chmod 777 "$TEST_FILE"
check_perm "777"

echo "Testing 644 (rw-r--r--)..."
chmod 644 "$TEST_FILE"
check_perm "644"

echo "Testing 000 (---------)..."
chmod 000 "$TEST_FILE"
check_perm "0"

# 3. Test Symbolic Modes
echo -e "\n${BLUE}--- Testing Symbolic Modes ---${NC}"

# Start from known state
chmod 600 "$TEST_FILE"

echo "Testing +x (Adding execute to all)..."
chmod +x "$TEST_FILE"
# 600 + 111 = 711
check_perm "711"

echo "Testing u-w (Removing write from user)..."
chmod u-w "$TEST_FILE"
# 711 - 200 = 511
check_perm "511"

# 4. Test Special Bits (SUID, SGID, Sticky)
# This tests if your bitmask (fmode & ~S_IFMT) correctly handles high bits
echo -e "\n${BLUE}--- Testing Special Bits (SUID/SGID/Sticky) ---${NC}"

echo "Testing SUID (4755)..."
chmod 4755 "$TEST_FILE"
check_perm "4755"

echo "Testing SGID (2755)..."
chmod 2755 "$TEST_FILE"
check_perm "2755"

echo "Testing Sticky Bit (1755)..."
chmod 1755 "$TEST_FILE"
check_perm "1755"

# 5. Verification of ctime update
echo -e "\n${BLUE}--- Testing ctime update ---${NC}"
START_TIME=$(stat -c %Z "$TEST_FILE")
sleep 1.1 # Wait to ensure distinct timestamp
chmod 700 "$TEST_FILE"
END_TIME=$(stat -c %Z "$TEST_FILE")

if [ "$END_TIME" -gt "$START_TIME" ]; then
    echo -e "${GREEN}[PASS]${NC} ctime updated successfully."
else
    echo -e "${RED}[FAIL]${NC} ctime did not change!"
    echo "Start: $START_TIME"
    echo "End:   $END_TIME"
fi

# 6. Cleanup
rm -f "$TEST_FILE"
echo -e "\n${GREEN}=== All Chmod Tests Passed for FrostByteFS ===${NC}"