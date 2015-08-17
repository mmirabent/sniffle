# Sniffle

Passive network health monitoring

## TODO

* ~~Check for root early. Die if not~~
* ~~timeval difference in milliseconds function~~
* ~~Write a better README~~
* Add command line arguments
* ~~DNS reverse lookups~~
    * ~~switch from dig to syscall implementation~~
* Data visualization? Maybe?
* ~~Write more TODOs~~
* ~~Figure out an appropriate license~~
* Basic usage documentation
* Command Line Options
    * Output options
        * CSV output
    * Input options (live or .pcap file)
        * live capture
        * .pcap file

## Tentative flags

| Short 	| Long          	| Description                              	|
|-------	|---------------	|------------------------------------------	|
| -n    	| --reverse-dns 	| output hostnames instead of IP addresses 	|
| -l    	| --live        	| use live network traffic for capture     	|
| -f    	| --file-input  	| use pcap file capture                    	|
| -o    	| --csv-output  	| output to csv file                       	|
| -s    	| --size        	| number of half open connections tracked  	|
| -h    	| --help        	| help I need somebody                     	|  

## Usage

Compile with `make`. Run with sudo, open up your browser and generate
some traffic.
