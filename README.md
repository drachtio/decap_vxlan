# decap_vxlan

A simple utility for extracting VXLAN-encapsulated network traffic and writing it to a new pcap file.  This is useful when you are mirroring traffic to a monitoring server and then want to strip out the VXLAN headers and leave a pcap file as it would look if captured on the target server.

## Requirements
On a Debian server
```bash
sudo apt-get install libpcap-dev build-essential
make
```

## Running
```bash
cat input.pcap | ./decap_vxlan > output.pcap
```