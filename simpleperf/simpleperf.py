import argparse
import socket
import sys
import threading
import time

# Global variables
# Size of one kilo byte
KILOBIT = 1000  # CONSTANT
default_ip = "127.0.0.1"
transmissions = []
final_transmissions = []
summary_print_index = 0
formating_line = "-" * 45
printheader = True
interval_totaltime = 0.0
interval_timer_thread = False


class Transmission:
    def __init__(self, ip_port_pair, elapsed_time, data_sent, total_bytes):
        self.ip_port_pair = ip_port_pair
        self.elapsed_time = elapsed_time
        self.data_sent = data_sent
        self.total_bytes = total_bytes


def print_error(error):
    print("\033[1;31;1mError: \n\t" + error + "\n\033[0m")


def print_server():
    print(formating_line)
    print("A simpleperf server is listening on port {}".format(args.port))
    print(formating_line)


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


parser = argparse.ArgumentParser(description="Simpleperf, a simple iPerf clone for testing network performance.",
                                 epilog="end of help")

# Client arguments
client_group = parser.add_argument_group('client')
client_group.add_argument('-c', '--client', action="store_true", help="Start the client")
client_group.add_argument('-I', '--serverip', type=check_ip, default="127.0.0.1",
                          help="Server ip address, default %(default)s")
client_group.add_argument('-t', '--time', type=check_positive, default="25",
                          help="Time to run the client in seconds, it will try to send as many packets as possible in the given time. Default %(default)s")
client_group.add_argument('-i', '--interval', type=check_positive)
client_group.add_argument('-P', '--parallel', type=int, default="1", choices=range(1, 6),
                          help="Number of parallel clients, default %(default)s")
client_group.add_argument('-n', '--num', type=check_nbytes,
                          help="Number of bytes to send i.e 10MB. Valid units B, MB or KB.")

# Server arguments
server_group = parser.add_argument_group('server')
server_group.add_argument('-s', '--server', action="store_true", help="Start the server")
server_group.add_argument('-b', '--bind', type=check_ip, default="127.0.0.1",
                          help="Bind the server to a specific ip address, default %(default)s")

# Common arguments
parser.add_argument('-p', '--port', type=check_port, default="8088", help="Port to use, default default %(default)s")
parser.add_argument('-f', '--format', type=str, default="MB", choices=("B", "KB", "MB"),
                    help="Format to print the data in, default %(default)s")

args = parser.parse_args()


def general_summary(server):
    # Set the total time to 0, this will be used to calculate the interval
    # global total_time
    total_time = 0.0

    global interval_totaltime
    global transmissions
    global final_transmissions

    if server:
        print("\n{:<15s}{:^15s}{:^15s}{:^15s}".format("ID", "Interval", "Received", "Rate"))
    else:
        # Print the header of the summary table only once if we are the client
        global printheader
        if printheader is True:
            print("\n{:<15s}{:^15s}{:^15s}{:^15s}".format("ID", "Interval", "Transfer", "Bandwidth"))
            printheader = False

    if len(transmissions) == 0:
        return

    # Calculate the packet size in bytes
    FORMAT_BIT = 0
    FORMAT_RATE = "Bps"

    # Convert the data_total bytes to the desired format i.e B, KB or MB from --format
    if args.format == "B":
        FORMAT_BIT = 1
        FORMAT_RATE = "Bps"
    elif args.format == "KB":
        FORMAT_BIT = 1 / KILOBIT
        FORMAT_RATE = "KBps"
    elif args.format == "MB":
        FORMAT_BIT = 1 / (KILOBIT * KILOBIT)
        FORMAT_RATE = "MBps"

    global summary_print_index

    # Loop through all the transmissions
    for j in range(summary_print_index, len(transmissions)):
        (ip_port_pair, elapsed_time, data_sent, total_sent) = transmissions[j]

        if summary_print_index == j:
            if data_sent != 0 or server or args.interval is None:
                # If the client are using the -i flag, we need to calculate the interval time
                if args.interval is not None:
                    total_time = interval_totaltime
                    elapsed_time = interval_totaltime + args.interval
                    # Convert the received bytes to the desired format i.e B, KB or MB from --format
                    received = data_sent * FORMAT_BIT
                else:
                    received = total_sent * FORMAT_BIT

                # Format the values to 2 decimal places and add the units
                f_start_time = round(total_time, 2)
                f_end_time = round(elapsed_time, 2)
                f_received = str(round(received, 2)) + args.format
                f_rate = str(round((received / elapsed_time) * 8, 2)) + " " + FORMAT_RATE
                # Print the summary of the transmission
                print("{:^15s}{:^15s}{:^15s}{:^15s}".format(ip_port_pair, "{} - {}".format(f_start_time, f_end_time),
                                                            f_received, f_rate))

            # Add the transmission to the final_transmissions list if it's the last transmission
            if data_sent == 0 or server:
                # Convert the total bytes to the desired format i.e B, KB or MB from --format
                total_sent = round(total_sent * FORMAT_BIT, 2)
                final_transmissions.append((ip_port_pair, elapsed_time, data_sent, total_sent))

        # Increment the summary_print_index, this is used to print the summary only once
        summary_print_index += 1

    if args.interval is not None:
        interval_totaltime += args.interval

    # if server:
    #    print_total()


def print_total():
    global final_transmissions
    if len(final_transmissions) != args.parallel:
        # Wait for the other clients to finish before printing the total
        time.sleep(0.1)

    print(formating_line)
    for (ip_port_pair, elapsed_time, data_sent, total_sent) in final_transmissions:
        print("Total sent {}{} to {}".format(total_sent, args.format, ip_port_pair))
        # final_transmissions.remove((ip_port_pair, elapsed_time, data_sent, total_sent))
    final_transmissions.clear()


def start_client():
    try:

        # Use the global variables
        global KILOBIT
        global transmissions

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

        # Keep track of how many bytes we have sent in this interval
        data_sent = 0

        # Print the client ip and port if we are using multiple clients
        if args.parallel == 1:
            print("Client connected to server {}, port {}".format(args.serverip, args.port))
        else:
            print("Client {}:{} connected with server {}, port {}".format(sock.getsockname()[0],
                                                                          sock.getsockname()[1], args.serverip,
                                                                          args.port))
        # Set the next interval to 0
        interval = 0
        # If the user has specified an interval, set the next interval to the current time + the interval
        if args.interval is not None:
            interval = time.time() + int(args.interval)

        if args.num is not None:
            # Size of the data to send in bytes
            packet_size = 0

            # Get the size of the packet from the user argument and convert it to the correct size
            if args.num.endswith("MB"):
                packet_size = int(args.num[:-2]) * KILOBIT * KILOBIT
            elif args.num.endswith("KB"):
                packet_size = int(args.num[:-2]) * KILOBIT
            elif args.num.endswith("B"):
                packet_size = int(args.num[:-1])

            # Fill a buffer with bytes
            dump = b'\x10' * packet_size

            while total_sent < packet_size:
                # Devide the packet size by the KILOBIT to get the number of chunks
                bytes_to_send = min(KILOBIT, packet_size - total_sent)
                # Send the data in chunks of 1KB
                sock.send(dump[:bytes_to_send])
                # Update the total sent
                total_sent += bytes_to_send
                # Update the total sent
                data_sent += KILOBIT
                # Update the elapsed time
                elapsed_time = time.time() - start_time
                if time.time() > interval != 0:
                    interval = time.time() + int(args.interval)
                    transmissions.append((ip_port_pair, elapsed_time, data_sent, total_sent))
                    data_sent = 0
        else:
            data_sent = 0

            # Send data for a certain amount of time
            runtime = time.time() + int(args.time)
            while time.time() <= runtime:
                # Send the data in chunks of KILOBIT
                sock.send(b'\x10' * KILOBIT)
                total_sent += KILOBIT
                # Update the total sent
                data_sent += KILOBIT
                # Update the elapsed time
                elapsed_time = time.time() - start_time
                if time.time() > interval != 0:
                    interval = time.time() + int(args.interval)
                    transmissions.append((ip_port_pair, elapsed_time, data_sent, total_sent))
                    data_sent = 0

        # Graceful close of connection by sending BYE
        sock.send("BYE".encode())

        # Then wait for the server to close the connection
        response = sock.recv(KILOBIT).decode()
        if response == "ACK:BYE":
            # Close the socket
            sock.close()
            elapsed_time = time.time() - start_time
            # data_sent = total_sent
            # Update the transmission
            transmissions.append((ip_port_pair, elapsed_time, 0, total_sent))

    except ConnectionRefusedError:
        print("Connection refused. Please check the host and port, and try again.")
        exit(1)


def handle_client(c_socket, c_addr):
    # Create the ip:port pair
    ip_port_pair = c_addr[0] + ":" + str(c_addr[1])
    print_server()
    print("\nA simpleperf client with {} is connected with {}:{}".format(ip_port_pair, args.bind, args.port))

    # Get the global variable for the server_transmissions
    global transmissions
    # Current time
    start_time = time.time()
    # Size of the packet
    total_received = 0
    while True:
        # Get the request
        packet = c_socket.recv(KILOBIT)
        # Add the size of the packet
        total_received += len(packet)
        # Remove the escape character
        packet = packet.strip(b'\x10')
        # Decode the packet
        packet = packet.decode()

        # Check if the client wants to EXIT
        if packet == "BYE":
            # Update the elapsed time one last time
            elapsed_time = time.time()
            total_received -= len("BYE")
            # Send the response
            c_socket.send("ACK:BYE".encode())
            # Close the socket after sending the response
            c_socket.close()
            # Save the results of the transmission
            transmissions.append((ip_port_pair, elapsed_time - start_time, total_received, total_received))
            break
    general_summary(True)


def interval_timer(client_treads):
    # Print statistics every interval, until all clients have finished
    while len(client_treads) != 0:
        # Wait for the interval
        time.sleep(args.interval)
        # Print the summary
        general_summary(False)
        # Remove the threads that have finished
        for client in client_treads:
            if not client.is_alive():
                client_treads.remove(client)


def start_server():
    # Create socket
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try to bind to the ip and port and accept connections
    try:
        # Bind the socket to the host and port
        s_socket.bind((args.bind, int(args.port)))
        print_server()  # Print the server info
    except socket.error:
        print("Failed to bind socket, maybe is the port and ip is taken already?")
        sys.exit(1)

    # Start listening for connections
    s_socket.listen()
    while True:
        # Accept connections
        c_socket, c_addr = s_socket.accept()
        # Create a new thread for each client to handle the connection
        threading.Thread(target=handle_client, args=(c_socket, c_addr)).start()


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
    # interval_tread = None
    # Check if the user specified the interval
    # if args.interval is not None:
    # Start the interval timer if the user specified the interval
    # interval_tread = threading.Timer(int(args.interval), interval_timer).start()
    # threading.Timer(int(args.interval), printHi).start()
    # threading.Thread(target=interval_timer).start()
    # threading.Timer(int(args.interval), printHi).start()
    # interval_tread = True

    print(formating_line)
    print("A simpleperf client connecting to server {}, port {}".format(args.serverip, args.port))
    print(formating_line)

    # Create a list of threads
    client_treads = []
    # Start the clients with the specified number of parallel clients
    for i in range(0, args.parallel):
        # Start the client
        client = threading.Thread(target=start_client)
        client.start()
        client_treads.append(client)

    # Check if ineterval is set, if not wait for all clients to finish then print the summary
    if args.interval is None:
        # Wait for all clients to finish
        for client in client_treads:
            client.join()
        # Print the summary
        general_summary(False)
    else:
        interval_timer(client_treads)
        # Wait for all clients to finish
    time.sleep(0.5)
    print_total()
