import socket
import sys
import hashlib
import time

def initiate(UDPsocket, ip_address, receiver_port, unique_id):
    
    # Formulate the Intent Message and send to the receiver
    Message = "ID" + unique_id
    Message = Message.encode()

    dropped = 1 # Eventually becomes 0 if Initiate Message is acked

    while (dropped == 1):

        # Send Initiate Message
        UDPsocket.sendto(Message,(ip_address, receiver_port))

        # Set timeout
        global timeout
        UDPsocket.settimeout(30)

        try:
            # Receive Accept Message from the receiver
            data, addr = UDPsocket.recvfrom(1024)

            # Remove the timeout
            UDPsocket.settimeout(None)

            # Set dropped to 0, indicating that the Initiate Message was acknowledged
            dropped = 0
            
            # Obtain the transaction ID from the Accept Message
            global transaction_id
            transaction_id = data.decode()
            print("Transaction ID: " + transaction_id)

        except socket.timeout:  # Catch the Exception Error
            # Timeout occured
            print("TIMEOUT! Client did not receive any Accept Message within 30 seconds.")
            print("Exiting...")
            exit()
            continue    # Reenter while loop
    

# Reads the payload from the text file
def payload_getter(file_path):
    file = open(file_path, "r")

    # Place the contents of the file to payload global variable
    global payload
    payload = file.read()
    print("PAYLOAD: " + payload)

# Computes the checksum of the payload
def compute_checksum(packet):
    return hashlib.md5(packet.encode('utf-8')).hexdigest()

# Ceiling division
def cdiv(x, y):
    return - (x // -y)

# Payload length analyzer
def payload_analyzer(UDPsocket, ip_address, receiver_port, unique_id, transaction_id, payload):

    # Initialize split into
    split_into = 4

    dropped = 1 # Eventually becomes 0 if 1st packet has already been acked

    while (dropped == 1):
        # Set payload length to ceiling of |payload|/ split_into
        length = cdiv(len(payload), split_into)
        print("Current Payload Length: " + str(length))

        # Split the payload into pieces of indicated length
        split_payload = [payload[s:s+length] for s in range(0, len(payload), length)]

        # Initialize packets list
        packets = list()

        last = 0
        # Format the packets to be sent beforehand
        for q in range(0, len(split_payload)):
            if q == len(split_payload)-1:
                last = 1

            # Formulates the packet content
            packet = "ID" + str(unique_id).zfill(8) + "SN" + str(q).zfill(7) \
                    + "TXN" + str(transaction_id).zfill(7) + "LAST" + str(last) + split_payload[q]

            # Gets the checksum
            checksum = compute_checksum(packet)
            
            # Encode packet using UTF-8 encoding
            packet = packet.encode()

            # Stores the packet and checksum to the packets list
            packets.append([packet, checksum])
        
        # Set timer
        start = time.time()

        # Send the very first packet
        UDPsocket.sendto(packets[0][0],(ip_address, receiver_port))

        # Set timeout
        global timeout
        UDPsocket.settimeout(timeout)

        try:
            # Receive ACK from the receiver
            data, addr = UDPsocket.recvfrom(1024)

            # Remove the timeout
            UDPsocket.settimeout(None)

            # Calculate new timeout based on the duration of FIRST packet exchange
            end = time.time()
            timeout = end - start

            print("Initial Timeout Duration: " + str(timeout))
            print("Obtained Payload Length: " + str(length))

            # Declare the start of packet sending
            print("!--- START ---! ")

            # Print the 1st ACK
            Message = data.decode()

            # Print the ACK received
            print("--- " + Message)

            # Compare checksums
            does_match = (Message[23:] == packets[0][1])
            print("      Checksums Match? -> " + str(does_match))

            # Print the Highest ACK number so far
            print("      Highest ACK: " + str(Message[3:10]))
            
            # Set dropped to 0, indicating that the packets were all acknowledged
            dropped = 0

        except socket.timeout:  # Catch the Exception Error
            # Timeout occured
            print("TIMEOUT! Packet may have been dropped.")
            
            # Reduce payload length (it may have been the reason for packet being dropped)
            split_into *= 2
            
            continue    # Reenter while loop

        break
        
    return packets

# Sends the data to the receiver
def send_packets(UDPsocket, ip_address, receiver_port, unique_id, transaction_id, payload):
    
    # Divide the payload into segments of length L
    packets = payload_analyzer(UDPsocket, ip_address, receiver_port, unique_id, transaction_id, payload)

    # Initialize count (number of packets sent at a time. Default is 3)
    count = 3

    # Initialize highest ack so far
    highest_ack = 0     # ACK 0 has been received through payload_analyzer()

    # Start sending packets at index 1. Packet at index 0 has already been sent through payload_analyzer()
    i = 1

    while True:
        dropped = 1 # Eventually becomes 0 if packets are acked

        while (dropped == 1):

            # Send packet by multiple of 'count'
            for t in range(min(count, len(packets)-i)):
                UDPsocket.sendto(packets[i+t][0],(ip_address, receiver_port))
                print("Packet " + str(i+t) + " SENT.")

            # Set timeout (Adding grace period of 0.75 seconds per packet)
            global timeout
            send_timeout = timeout + (min(count, len(packets)-i)*1)
            UDPsocket.settimeout(send_timeout)
            print("Waiting for " + str(send_timeout) + " seconds.")

            try:
                # Receive ACK from the receiver by multiple of 'count'
                for t in range(min(count, len(packets)-i)):
                    data, addr = UDPsocket.recvfrom(1024)
                    
                    Message = data.decode()

                    # Print the ACK received
                    print("--- " + Message)

                    # Update highest ack based on received ACK message
                    new_ack = int(Message[3:10])
                    if new_ack > highest_ack:
                        highest_ack = new_ack

                    # Update the index of packet sending
                    i = highest_ack + 1

                    # Compare checksums
                    does_match = (Message[23:] == packets[new_ack][1])
                    print("      Checksums Match? -> " + str(does_match))

                    # Print the Highest ACK number so far
                    print("      Highest ACK: " + str(highest_ack))
                
                # Remove the timeout
                UDPsocket.settimeout(None)

                # Set dropped to 0, indicating that the packets were all acknowledged
                dropped = 0

                # Increase count (number of packets sent at a time)
                count += 1

            except socket.timeout:  # Catch the Exception Error
                # Timeout occured
                print("TIMEOUT! Packet may have been dropped.")
                dropped = 1
                
                # Reduce count (number of packets sent at a time)
                if count > 2:
                    count -= 1

                # Reenter while loop
                continue

        
        # Break the loop if all packets have already been sent and ACKed
        if highest_ack == len(packets)-1:
            break    


#### MAIN ####

# Argument list
arg_list = sys.argv

# Argument elements default value
file_path = "fc36c664.txt"
ip_address = "10.0.7.141"
receiver_port = "9000"
sender_port = "6692"
unique_id = "fc36c664"

# Argument parser
for i in range(len(arg_list)):
    if arg_list[i] == '-f':
        if(arg_list[i+1]):
            file_path = arg_list[i+1]
    if arg_list[i] == '-a':
        if(arg_list[i+1]):
            ip_address = arg_list[i+1]
    if arg_list[i] == '-s':
        if(arg_list[i+1]):
            receiver_port = arg_list[i+1]
    if arg_list[i] == '-c':
        if(arg_list[i+1]):
            sender_port = arg_list[i+1]
    if arg_list[i] == '-i':
        if(arg_list[i+1]):
            unique_id = arg_list[i+1]


# UDP Socket
UDPsocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
UDPsocket.bind(("", int(sender_port)))

# Transaction ID placeholder
transaction_id = ""

# Payload placeholder
payload = ""

# Get the payload from the indicated file
payload_getter(file_path)

# Initial timeout duration
timeout = 6

# Start the clock
start = time.time()

# Send an Initiate Message
initiate(UDPsocket, ip_address, int(receiver_port), unique_id)

# Begin sending packets
send_packets(UDPsocket, ip_address, int(receiver_port), unique_id, transaction_id, payload)

# Stop the clock
end = time.time()

# Print the time taken to send the whole data
print("Time Taken: " + str(end - start) + " seconds")

