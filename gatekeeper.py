import socket
import argparse
import signal
import sys
from threading import Thread
import time
import random

# List of predefined ports
PREDEFINED_PORTS = [1, 22, 53, 80, 88, 443, 1234, 8443, 8080, 60444]

# Function to handle incoming connections
def handle_client(client_socket, port):
    print(f"Connection received on port {port} from {client_socket.getpeername()}")
    client_socket.close()

# Function to start a server on a specific port
def start_server(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    print(f"Listening on {ip}:{port}")

    while True:
        client_socket, addr = server.accept()
        client_handler = Thread(target=handle_client, args=(client_socket, port))
        client_handler.start()

# Function to handle the signal interrupt
def signal_handler(sig, frame):
    print("\nExiting the program...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Listen for connections on predefined or random ports.")
    parser.add_argument("ip", type=str, help="IP address to bind the servers to.")
    parser.add_argument("-r", action="store_true", help="Open 1000 random ports.")
    parser.add_argument("-a", action="store_true", help="Open all 65535 ports.")

    args = parser.parse_args()
    ip = args.ip
    rando = args.r
    goloco = args.a

    # Register the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    threads = []
    if goloco:
        ports = range(1, 65536)
    elif rando:
        ports = random.sample(range(1, 65536), 1000)
    else:
        ports = PREDEFINED_PORTS

    for port in ports:
        server_thread = Thread(target=start_server, args=(ip, port))
        server_thread.daemon = True  # Allow threads to exit when main program exits
        server_thread.start()
        threads.append(server_thread)

    # Keep the main thread alive to handle signal
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()
