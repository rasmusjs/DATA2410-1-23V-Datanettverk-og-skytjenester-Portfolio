import argparse
import socket
import sys
import threading
import time

# Global variables
# Size of one kilo byte
kilobyte = 1000
default_ip = "127.0.0.1"
server_transmissions = []
client_transmissions = []
formating_line = "-" * 45


class Transmission:
    def __init__(self, ip_port_pair, elapsed_time, packet_size):
        self.ip_port_pair = ip_port_pair
        self.elapsed_time = elapsed_time
        self.packet_size = packet_size


def print_error(error):
    print("\033[1;31;1mError: \n\t" + error + "\n\033[0m")


def check_positive(val):
    try:
        val = int(val)
        if val <= 0:
            print_error(str(val) + " is not a valid number, must be positive")
            raise argparse.ArgumentTypeError(str(val) + " is not a valid number, must be positive")
    except ValueError:
        print_error('expected an integer but you entered a string')
        raise argparse.ArgumentTypeError('expected an integer but you entered a string')
    return val


def check_port(port):
    try:
        port = int(port)
        if 1024 > port:
            print_error("Port number is too small, the port must be from 1024 upto 65535")
            raise argparse.ArgumentTypeError("Port number is too small, the port must be from 1024 upto 65535")

        if 65535 < port:
            print_error("Port number is too large, the port must be from 1024 upto 65535")
            raise argparse.ArgumentTypeError("Port number is too large, the port must be from 1024 upto 65535")
    except ValueError:
        print_error('expected an integer but you entered a string')
        raise argparse.ArgumentTypeError('expected an integer but you entered a string')
    return port


def check_ip(ip):
    # Split the ip into a list
    ip_split = ip.split(".")

    try:
        # Check if we have 3 dots in the ip
        if len(ip_split) != 4:
            print_error(ip + " is not valid ip")
            raise argparse.ArgumentTypeError(ip + " is not valid ip")

        # Check if we start or end with 0
        if int(ip_split[0]) == 0 or int(ip_split[3]) == 0:
            print_error(ip + " cannot start or end with 0")
            raise argparse.ArgumentTypeError(ip + " cannot start or end with 0")

        # Check if numbers are in range
        for number in ip_split:
            if 0 > int(number):
                print_error(number + " invalid too small number")
                raise ValueError(number + " invalid too large number")

            # If number is larger
            if 255 < int(number):
                print_error(number + " invalid too large number")
                raise ValueError(number + " invalid too large number")

    except ValueError:
        raise argparse.ArgumentTypeError(ip_split + " is not valid ip")

    return ip


def check_nbytes(nbytes):
    if nbytes.endswith("MB"):
        print("MB choosen")
        return nbytes
    elif nbytes.endswith("KB"):
        print("KB choosen")
        return nbytes
    elif nbytes.endswith("B"):
        print("B choosen")
        return nbytes
    else:
        print_error("Invalid numbers to send must end with B, KB or MB. " + nbytes + " is not recognized")
        raise argparse.ArgumentTypeError(
            "Invalid numbers to send must end with B, KB or MB. " + nbytes + " is not recognized")


parser = argparse.ArgumentParser(description="Optional arguments", epilog="end of help")

# Client
parser.add_argument('-c', '--client', action="store_true", help="Start the client")

parser.add_argument('-I', '--serverip', type=check_ip, default="127.0.0.1",
                    help="Server ip address, default %(default)s")
parser.add_argument('-t', '--time', type=check_positive, default="50",
                    help="Time to run the client in seconds, it will try to send as many packets as possible in the given time. Default %(default)s")
parser.add_argument('-i', '--interval', type=check_positive)
parser.add_argument('-P', '--parallel', type=int, default="1", choices=range(1, 6),
                    help="Number of parallel clients, default %(default)s")
parser.add_argument('-n', '--num', type=check_nbytes, help="Number of bytes to send i.e 10MB. Valid units B, MB or KB.")

# parser.addgroup()!!

# Server
parser.add_argument('-s', '--server', action="store_true", help="Start the server")
parser.add_argument('-b', '--bind', type=check_ip, default="127.0.0.1",
                    help="Bind the server to a specific ip address, default %(default)s")

# Common Args
parser.add_argument('-p', '--port', type=check_port, default="8088", help="Port to use, default 8088")
parser.add_argument('-f', '--format', type=str, default="MB", choices=("B", "KB", "MB"),
                    help="Format to print the data in, default %(default)s")

args = parser.parse_args()


def general_summary(server):
    # Set the total time to 0, this will be used to calculate the interval
    total_time = 0.0

    # transmissions = []
    # Print the header of the summary table depending on if we are the server or client
    if server:
        global server_transmissions
        transmissions = server_transmissions
        print("ID\tInterval\tReceived\tRate")
    else:
        global client_transmissions
        transmissions = client_transmissions
        print("ID\tInterval\tTransfer\tBandwidth")

    # Loop through all the transmissions
    for (ip_port_pair, elapsed_time, received) in transmissions:

        # Convert the packet_size bytes to the desired format i.e B, KB or MB from --format
        if args.format == "B":
            received = received
        elif args.format == "KB":
            received = received / kilobyte
        elif args.format == "MB":
            received = received / kilobyte / kilobyte

        # Format the values to 2 decimal places and add the units
        f_total_time = round(total_time, 2)
        f_end_time = round(total_time + elapsed_time, 2)
        f_received = str(round(received, 2)) + args.format
        f_rate = str(round((received / elapsed_time), 2)) + args.format + "/s"

        # Print the summary of the transmission
        print("{}\t{} - {}\t{}\t{}".format(ip_port_pair, f_total_time, f_end_time, f_received, f_rate))
        # Add the elapsed time to the total time
        total_time += elapsed_time


def start_client():
    try:
        print(formating_line)
        print("A simpleperf client connecting to server {}, port {}".format(args.serverip, args.port))
        # Check if we are connecting to one server or multiple
        print(formating_line)

        # Use the global kilobyte
        global kilobyte

        global client_transmissions

        # Keep track of how many bytes we have sent in total
        total_sent = 0

        start_time = time.time()
        # Try to connect to the server

        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the host and port
        sock.connect((args.serverip, args.port))
        # Get the ip and port of the client
        ip_port_pair = str(sock.getsockname()[0]) + ":" + str(sock.getsockname()[1])

        # Print the client ip and port if we are using multiple clients
        if args.parallel == 1:
            print("Client connecting to server {}, port {}".format(args.serverip, args.port))
        else:
            print("Client IP: port connected with {}, port {}".format(args.serverip, sock.getsockname()[1]))

        if args.num is not None:
            # Size of the data to send
            packet_size = 0

            # Get the size of the packet from the user argument and convert it to bytes
            if args.num.endswith("MB"):
                packet_size = int(args.num[:-2]) * kilobyte * kilobyte
            elif args.num.endswith("KB"):
                packet_size = int(args.num[:-2]) * kilobyte
            elif args.num.endswith("B"):
                packet_size = int(args.num[:-1])

            # Fill a buffer with bytes
            dump = b'\x10' * packet_size

            while total_sent < packet_size:
                # Send the data in chunks of 1KB
                bytes_to_send = min(kilobyte, packet_size - total_sent)
                # Send the data
                sock.send(dump[:bytes_to_send])
                # Update the total sent
                total_sent += bytes_to_send
        else:
            # Send data for a certain amount of time
            runtime = time.time() + int(args.time)

            while time.time() <= runtime:
                # Send the data in chunks of kilobyte
                sock.send(b'\x10' * kilobyte)
                total_sent += kilobyte

        # Send the final command
        sock.send("BYE".encode())

        # Get the response
        response = sock.recv(kilobyte).decode()
        if response == "ACK:BYE":
            # Close the socket
            sock.close()
            elapsed_time = time.time() - start_time
            client_transmissions.append((ip_port_pair, elapsed_time, total_sent))
            # Print the summary

    except ConnectionRefusedError:
        print("Connection refused. Please check the host and port, and try again.")
        exit(1)


def handle_client(c_socket, c_addr):
    # Create the ip:port pair
    ip_port_pair = c_addr[0] + ":" + str(c_addr[1])

    print(formating_line)
    print("A simpleperf client with {} is connected with {}:{}. \n".format(ip_port_pair, args.bind, args.port))
    print(formating_line)

    # Get the global variable for the server_transmissions
    global server_transmissions
    # Current time
    start_time = time.time()
    # Size of the packet
    total_size = 0
    while True:
        # Get the request
        packet = c_socket.recv(kilobyte)
        # Add the size of the packet
        total_size += len(packet)
        # Remove the escape character
        packet = packet.strip(b'\x10')
        # Decode the packet
        packet = packet.decode()

        # Check if the client wants to EXIT
        if packet == "BYE":
            total_size -= len("BYE")
            print("Received packet from client {}: {}".format(ip_port_pair, packet))
            # Send the response
            c_socket.send("ACK:BYE".encode())
            # Close the socket after sending the response
            c_socket.close()
            elapsed_time = time.time() - start_time
            server_transmissions.append((ip_port_pair, elapsed_time, total_size))
            break
    # Print the summary after the client has disconnected
    # printSummary()
    general_summary(True)


def interval_timer():
    # Get the global variable for the client_transmissions
    global client_transmissions
    # Check if we have received any data from the clients
    if len(client_transmissions) != 0:
        general_summary(False)


def start_server():
    # Create socket
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try to bind to the ip and port and accept connections
    try:
        # Bind the socket to the host and port
        s_socket.bind((args.bind, int(args.port)))
        print("A simpleperf server is listening on port {} \n".format(args.port))
    except socket.error:
        print("Failed to bind socket, maybe the port is already in use?")
        sys.exit(1)
    s_socket.listen()
    while True:
        # Accept connections
        c_socket, c_addr = s_socket.accept()
        # Create a new thread for each client to handle the connection
        client_worker = threading.Thread(target=handle_client, args=(c_socket, c_addr))
        client_worker.start()


if (args.server and args.client) or (not args.server and not args.client):
    print("Error: you must run either in server or client mode")
    parser.print_help()
    exit(1)

if args.server:
    # Try to bind to the ip and port
    # If it fails print error and exit
    # Start listening
    # Print statistics

    # Check if user used bind to set server ip
    if args.serverip != "127.0.0.1":
        print_error("Wrong use bind to set server ip")
        parser.print_help()
        exit(1)

    # Start the server
    start_server()

if args.client:

    # Check if user used bind to set server ip
    if args.bind != "127.0.0.1":
        print_error("Wrong use bind to set server ip")
        parser.print_help()
        exit(1)

    # Set a variable for the interval thread
    interval_tread = None
    # Check if the user specified the interval
    if args.interval is not None:
        # Start the interval timer if the user specified the interval
        interval_tread = threading.Timer(int(args.interval), interval_timer).start()

    # Create a list of threads
    client_treads = []
    # Start the clients with the specified number of parallel clients
    for i in range(0, args.parallel):
        # Start the client
        client = threading.Thread(target=start_client)
        client.start()
        client_treads.append(client)

    # Wait for all the threads to finish
    for client in client_treads:
        client.join()

    # Check if the user specified the interval
    if args.interval is None:
        general_summary(False)
    else:
        # Stop the interval timer
        interval_tread = None
        # Run the interval timer one last time to print the summary
        interval_timer()
