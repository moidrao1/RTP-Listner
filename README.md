# RTP-Listner

This basic application is used to capture RTP traffic from your local network.  ( Packet Sniffing )

The main idea behind this sniffing RTP packets are to record Call so this is only the capturing part. 

# Enviornment 

- Linux (Centos 6 or 7 )
- Gcc 
- Apache kafka 
- ZooKeeper

# Libraries 

- Librdkafka
- cppKafka for C++
- libPcap

# Installations

There is command.txt in repository which describes all basic command to run and install kafka and pcap.


# Note

This application will sniff packets according to our filter given in pcap object. After capturing relevant packets it push that packets to our Apache Kafka
topic in order to prevent any processing delay. 
Another thread which will be listening on apache kafkaa topic and will process that packet according to your need. 