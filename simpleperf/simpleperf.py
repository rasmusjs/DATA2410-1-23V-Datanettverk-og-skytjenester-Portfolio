import argparse
import socket
import sys
import _thread as thread
import time

# Global variables
# Size of one kilo byte
kilobyte = 1000
default_ip = "127.0.0.1"
server_transmissions = []
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
parser.add_argument('-I', '--serverip', type=check_ip, default="127.0.0.1", help="Server ip address, default 127.0.0.1")
parser.add_argument('-t', '--time', type=check_positive, default="50", help="Time to run the client in seconds, "
                                                                            "it will try to send as many packets as "
                                                                            "possible in the given time.")
parser.add_argument('-i', '--interval', type=check_positive, default="60")
parser.add_argument('-P', '--parallel', type=int, default="1", choices=range(1, 6), help="Number of parallel clients")
parser.add_argument('-n', '--num', type=check_nbytes, help="Number of bytes to send i.e 10MB. Valid units B, MB or KB.")

# Server
parser.add_argument('-s', '--server', action="store_true", help="Start the server")
parser.add_argument('-b', '--bind', type=check_ip, default="127.0.0.1",
                    help="Bind the server to a specific ip address, default 127.0.0.1")

# Common Args
parser.add_argument('-p', '--port', type=check_port, default="8088", help="Port to use, default 8088")
parser.add_argument('-f', '--format', type=str, default="MB", choices=("B", "KB", "MB"),
                    help="Format to print the data")

args = parser.parse_args()


def client_send_nmbytes():
    client_transmissions = []
    # Use the global kilobyte
    global kilobyte
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

    # Keep track of how many bytes we have sent in total
    total_sent = 0
    # Keep sending data until we have sent the packet size
    while total_sent < packet_size:
        start_time = time.time()
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the host and port
        sock.connect((args.serverip, args.port))
        # Get the ip and port of the client
        ip_port_pair = str(sock.getsockname()[0]) + ":" + str(sock.getsockname()[1])
        # Keep track of how many bytes we have sent with this socket
        socket_sent = 0
        # Send data for in the given interval
        interval = time.time() + int(args.interval)
        while time.time() <= interval and total_sent < packet_size:
            # Send the data in chunks of 1KB
            bytes_to_send = min(kilobyte, packet_size - total_sent)
            # Send the data
            sock.send(dump[:bytes_to_send])
            # Update the total sent
            total_sent += bytes_to_send
            socket_sent += bytes_to_send

        sock.send('FIN'.encode())
        response = sock.recv(kilobyte).decode()
        if response == "ACK":
            sock.close()
            elapsed_time = time.time() - start_time
            client_transmissions.append((ip_port_pair, elapsed_time, socket_sent))
    return client_transmissions


def client_send_time():
    # List to keep track of all the client threads
    client_transmissions = []
    # Use the global kilobyte
    global kilobyte
    total_sent = 0
    # Send data for a certain amount of time
    runtime = time.time() + int(args.time)
    while time.time() <= runtime:
        start_time = time.time()
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the host and port
        sock.connect((args.serverip, args.port))
        # Get the ip and port of the client
        ip_port_pair = str(sock.getsockname()[0]) + ":" + str(sock.getsockname()[1])
        # Send data for in the given interval
        interval = time.time() + int(args.interval)
        while time.time() <= interval:
            # Send the data in chunks of kilobyte
            sock.send(b'\x10' * kilobyte)
            total_sent += kilobyte

        # Send the final command
        sock.send("FIN".encode())

        # Get the response
        response = sock.recv(kilobyte).decode()
        if response == "ACK":
            # Close the socket
            sock.close()
            elapsed_time = time.time() - start_time
            client_transmissions.append((ip_port_pair, elapsed_time, total_sent))
            total_sent = 0
    # End of the while loop
    return client_transmissions


def general_summary(transmissions, server):
    # Set the total time to 0, this will be used to calculate the interval
    total_time = 0.0

    # Print the header of the summary table depending on if we are the server or client
    if server:
        print("ID\tInterval\tReceived\tRate")
    else:
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
        # Check if we are connecting to one server or multiple
        if args.parallel == 1:
            print(
                "A simpleperf client Client connecting to server {}, port {}".format(args.serverip, args.port))
        else:
            print("A simpleperf client connecting to server {}, port {}".format(args.serverip, args.port))
        print(formating_line)

        # Try to connect to the server
        if args.num is not None:
            general_summary(client_send_nmbytes(), False)

        else:
            # Send data for a certain amount of time
            general_summary(client_send_time(), False)

    except ConnectionRefusedError:
        print("Connection refused. Please check the host and port, and try again.")
        exit(1)


def client_thread(c_socket, c_addr):
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
        if packet == "FIN":
            total_size -= len("FIN")
            # Send the response
            c_socket.send("ACK".encode())
            # Close the socket after sending the response
            c_socket.close()
            elapsed_time = time.time() - start_time
            server_transmissions.append((ip_port_pair, elapsed_time, total_size))
            break
    # Print the summary after the client has disconnected
    # printSummary()
    general_summary(server_transmissions, True)


def summary_countdown():
    # Get the global variable for the server_transmissions
    global server_transmissions
    # Wait for the time specified by the user
    time.sleep(int(args.interval))
    # Print the summary
    general_summary(server_transmissions, True)


def start_server():
    print("Starting server")
    # Create socket
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try to bind to the ip and port

    try:
        # Bind the socket to the host and port
        # print("Binding to " + args.server + ":" + str(args.port) + "\n")
        s_socket.bind((args.bind, int(args.port)))
        print("A simpleperf server is listening on port {} \n".format(args.port))
    except socket.error:
        print("Failed to bind socket, maybe the port is already in use?")
        sys.exit(1)
    s_socket.listen()
    while True:
        # Accept connections
        # Start receiving data
        # Print statistics
        c_socket, c_addr = s_socket.accept()
        thread.start_new_thread(client_thread, (c_socket, c_addr))
        # Check if the number of clients is equal to the number of parallel clients, if so exit

        # printSummary()
    # If it fails print error and exit
    # Start listening
    # Print statistics


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

    start_server()

if args.client:
    # Check if user used bind to set server ip
    if args.bind != "127.0.0.1":
        print_error("Wrong use bind to set server ip")
        parser.print_help()
        exit(1)

    # Create number of clients specified by parallel
    for i in range(args.parallel):
        start_client()

if args.server and args.client or not args.server and not args.client:
    print("Error: you must run either in server or client mode")
    parser.print_help()
