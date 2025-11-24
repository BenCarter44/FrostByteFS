#!/bin/bash

# Check if a filename was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

FILE="$1"
BLOCK_SIZE=4096

# Check if file exists
if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found."
    exit 1
fi

# Get file size (standard Linux stat command)
FILE_SIZE=$(stat -c%s "$FILE")

# Calculate total blocks needed (ceiling division)
TOTAL_BLOCKS=$(( (FILE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE ))

echo "Processing '$FILE' ($FILE_SIZE bytes) in $TOTAL_BLOCKS chunks of $BLOCK_SIZE bytes..."
echo "------------------------------------------------"

# Loop through the file
i=0
while [ "$i" -lt "$TOTAL_BLOCKS" ]; do
    # Extract 4KB chunk and pipe to sha1sum
    # bs=4096: Set block size
    # count=1: Read only one block
    # skip=$i: Skip the previous blocks
    # 2>/dev/null: Silence dd's status output
    CHECKSUM=$(dd if="$FILE" bs=$BLOCK_SIZE count=1 skip=$i 2>/dev/null | sha1sum | awk '{print $1}')
    
    # Calculate offset for display purposes
    OFFSET=$((i * BLOCK_SIZE))
    
    # Calculate the size of the current block
    # By default, it's the full block size, but the last one might be smaller
    BYTES_LEFT=$((FILE_SIZE - OFFSET))
    if [ "$BYTES_LEFT" -lt "$BLOCK_SIZE" ]; then
        CURRENT_SIZE=$BYTES_LEFT
    else
        CURRENT_SIZE=$BLOCK_SIZE
    fi
    
    # Prepare the output line
    OUTPUT_LINE="Offset $OFFSET Size $CURRENT_SIZE: $CHECKSUM"
    
    # If the block is small (less than 16 bytes), append the hex representation
    if [ "$CURRENT_SIZE" -lt 16 ]; then
        # Extract chunk again for hex dumping
        # od -An: No address/offset in output
        # -t x1: Output as 1-byte hex integers
        # tr -d ' \n': Remove all spaces and newlines for a compact string
        HEX_DATA=$(dd if="$FILE" bs=$BLOCK_SIZE count=1 skip=$i 2>/dev/null | od -An -t x1 | tr -d ' \n')
        OUTPUT_LINE="$OUTPUT_LINE [Hex: $HEX_DATA]"
    fi
    
    echo "$OUTPUT_LINE"
    
    i=$((i + 1))
done

echo "------------------------------------------------"
echo "Done."