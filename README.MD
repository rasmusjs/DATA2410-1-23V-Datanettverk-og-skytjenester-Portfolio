# SimplePerf

## A simple network throughput performance test tool

Simpleperf is a simple network throughput performance tool inspired by iPerf. It uses python sockets to send data
between a client(s) and a server using TCP. The client(s) can be run in parallel to simulate multiple clients.

### Dependencies

[Python 3](https://www.python.org/downloads/) is required to run simpleperf.If you are using a Debian (e.g. Ubuntu)
based system, you can install python3 with the following command:

```bash
sudo apt install python3
```

## Usage

### Example usage with a client using intervals and parallel clients

```bash
python3 simpleperf.py -c -I 127.0.0.1 -p 8088 -P 2 -t 15 -i 5
---------------------------------------------
A simpleperf client connecting to server 127.0.0.1, port 8088
---------------------------------------------
Client 127.0.0.1:50458 connected with server 127.0.0.1, port 8088
Client 127.0.0.1:50472 connected with server 127.0.0.1, port 8088

ID                Interval       Transfer       Bandwidth   
127.0.0.1:50472   0.0 - 5.0      168.57 MB     269.71 Mbps  
127.0.0.1:50458   0.0 - 5.0      182.09 MB     291.35 Mbps  
127.0.0.1:50472  5.0 - 10.0      175.76 MB     281.21 Mbps  
127.0.0.1:50458  5.0 - 10.0      203.58 MB     325.74 Mbps  
127.0.0.1:50458  10.0 - 15.0     178.18 MB     285.09 Mbps  
127.0.0.1:50472  10.0 - 15.0     183.16 MB     293.05 Mbps  
---------------------------------------------
Total 127.0.0.1:50458   0 - 15.39      567.1 MB      294.75 Mbps  
Total 127.0.0.1:50472   0 - 15.42      529.44 MB     274.72 Mbps 
```

### Client

| Client arguments:                                  	 | 	      Description:                                                                                                         |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| -c, --client                           	             | Start in client mode                                                                                                      	 |
| -I SERVERIP, --serverip                	             | Server ip address to connect to. Default 127.0.0.1                                                                        	 |
| -t TIME, --time                        	             | Time to run the client in seconds, it will try to send as many packets as possible in the given time. Default 25 secounds 	 |
| -i INTERVAL, --interval                	             | Print statistics every x seconds.                                                                                         	 |
| -P {1,2,3,4,5}, --parallel {1,2,3,4,5} 	             | Number of parallel clients. Default 1 client                                                                              	 |
| -n NUM, --num                          	             | Number of bytes to send I.e 10MB. Valid units B, MB or KB.                                                                	 |

### Server

| Server arguments:         	 | 	                            Description:                     |
|-----------------------------|---------------------------------------------------------------|
| -s, --server    	           | Start in server mode                                        	 |
| -b BIND, --bind 	           | Bind the server to a specific ip address. Default 127.0.0.1 	 |

### Common arguments

| Common arguments:     	            | Description                             	 |
|:-----------------------------------|:------------------------------------------|
| -h, --help                       	 | show this help message and exit         	 |
| -p PORT, --port                  	 | Port to use, default default 8088       	 |
| -f {B,KB,MB}, --format {B,KB,MB} 	 | Format to print the data in, default MB 	 |