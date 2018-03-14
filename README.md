# WireScope
Java Packet Sniffer using pcap4j

This is a simple Java packet sniffer that uses the [pcap4j](https://github.com/kaitoy/pcap4j) library to promiscuously sniff packets.  There is a simple GUI and is also able to export .pcap files.

#### System requirements ####
 
##### Libraries #####
* libpcap 1.1.1
* WinPcap 4.1.2
* jna 4.5.1
* slf4j-api 1.7.25
* pcap4j 1.7.3

##### Platforms ######
Should be compatible with multiple platforms but has only been tested on Windows 10

##### Others #####
Pcap4J needs administrator/root privileges.
Or, if on Linux, you can run Pcap4J with a non-root user by granting capabilities `CAP_NET_RAW` and `CAP_NET_ADMIN`
to your java command by the following command: `setcap cap_net_raw,cap_net_admin=eip /path/to/java`

#### Running ####
Make sure to include pcap4j-packetfactory-static-1.7.3.jar in the classpath when executing the program.  Failure to do so will result in the packets having an unknown type.

### License ###
WireScope is distributed under the MIT license.