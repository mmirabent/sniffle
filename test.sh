#!/bin/bash

# Very crude test script. Runs the sniffle program in live capture more and 
# uses a python script to generate a bunch of TCP connections

# Check for root, die if not
if [ $UID -ne 0 ];
then
    echo Must be root;
    exit;
fi

# Test the sniffle program
./sniffle -l &
SNIFFLE_PID=$!

# Generate TCP connections
python generate_connections.py

kill -9  $SNIFFLE_PID

