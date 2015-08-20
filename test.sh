#!/bin/bash

# Very crude test script. Runs the sniffle program in live capture more and 
# uses a python script to generate a bunch of TCP connections

# Check for root, die if not
if [ $UID -ne 0 ];
then
    echo Must be root;
    exit;
fi

# Test the live capture
echo Testing live capture
./sniffle -l &
SNIFFLE_PID=$!

# Generate TCP connections
python generate_connections.py

kill -9  $SNIFFLE_PID

echo Testing file input
tcpdump -c 100 -w /tmp/foo.pcap &

python generate_connections.py

wait

./sniffle -f /tmp/foo.pcap

echo Testing reverse DNS lookup
./sniffle -nf /tmp/foo.pcap

rm /tmp/foo.pcap

