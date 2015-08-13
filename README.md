# Sniffle

Passive network health monitoring

## TODO

* ~~timeval difference in milliseconds function~~
* ~~Write a better README~~
* Add command line arguments
* ~~DNS reverse lookups~~
    * switch from dig to syscall implementation
* Data visualization? Maybe?
* ~~Write more TODOs~~
* Figure out an appropriate license
* Basic usage documentation
* Command Line Options
    * Output options
      * CSV output
    * Input options (live or .pcap file)
      * live capture
      * .pcap file

* Flags
    * -n reverse DNS lookup
    * -l live capture
    * -f pcap file capture
    * -o csv file output
    * -s number of half open connections tracked
    * -h help

## Usage

Compile with `make`. Run with sudo, open up your browser and generate
some traffic.
