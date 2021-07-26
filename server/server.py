import socket
import threading
from AES_RSA.AES import AES
from AES_RSA.RSA import RSA

e, d, n = 0, 0, 0
key = [
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0
]
e_data = []
dec_message = [
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0
]
aes_key = False
socket_closed = False


# Socket Send function
def send(sock):
    global socket_closed
    while True:
        sen_data = input()

        # print available command
        if sen_data == "help":
            print("1. rsa_encrypt_key")
            print("\tSend RSA key to Client")
            print("2. quit")
            print("\tQuit Server")
            print("Send : ", end='')
            continue
        # quit Client
        elif sen_data == "quit":
            if not socket_closed:
                sock.send(sen_data.encode('utf-8'))
            print("Quit Server")
            break

        sock.send(sen_data.encode('utf-8'))

        # send RSA encrypt(public) key
        if sen_data == "rsa_encrypt_key":
            print("RSA encrypt key Sending")
            e_len = len(str(e))
            n_len = len(str(n))
            sock.send(str(e_len).encode('utf-8'))
            sock.send(str(n_len).encode('utf-8'))
            sock.send(str(e).encode('utf-8'))
            sock.send(str(n).encode('utf-8'))
            print("Send RSA encrypt key")
        print("Send : ", end='')


def receive(sock):
    global aes_key
    global socket_closed
    while True:
        rec_data = sock.recv(1024)

        # Client closed
        if rec_data.decode('utf-8') == "quit":
            socket_closed = True
            print("\nClient Quit")
            sock.send(rec_data)
            break
        # Receive encrypted AES key
        elif rec_data.decode('utf-8') == "encrypted_aes_key":
            aes_key = True

            print("\nEncrypted AES key sending")

            for i in range(16):
                key_len = sock.recv(3)
                key[i] = sock.recv(int(key_len.decode('utf-8')))
                key[i] = int(key[i].decode('utf-8'))
                key[i] = RSA.decrypt(key[i], d, n)

            print("Received AES encrypted key")
            print("Send : ", end='')
        # Receive encrypted ----.bmp file & decrypt ----.bmp file
        elif ".bmp" in rec_data.decode('utf-8'):
            # if AES key does not exist
            if not aes_key:
                print("\nNeed AES key")
                print("Send : ", end='')
            # AES key exists
            else:
                print("\nAES key exists")
                print("Receiving encrypted file")
                exist_file = sock.recv(1)
                # if client does not have ----.bmp file
                if exist_file.decode('utf-8') == '0':
                    print("No exists file")
                    print("Send : ", end='')
                    continue
                # receive ----.bmp file
                else:
                    file_name = rec_data
                    info_size = sock.recv(3)
                    data_size = sock.recv(10)

                    # receive file info(header), data size
                    info_size = int(info_size.decode('utf-8'))
                    data_size = int(data_size.decode('utf-8'))

                    info = []
                    data = []

                    # receive file info(header)
                    for i in range(info_size):
                        rec_info = sock.recv(1)
                        info.append(int(sock.recv(int(rec_info))))
                    # receive file data
                    for i in range(data_size):
                        rec_data = sock.recv(1)
                        data.append(int(sock.recv(int(rec_data))))

                    print("Received encrypted file")

                    f = open('received_' + file_name.decode('utf-8'), 'wb')
                    f.write(bytes(info))
                    f.write(bytes(data))
                    f.close()

                    print("Decrypting file")
                    aes = AES(key)
                    info, d_data = aes.aes_data_decrypt(info, data)

                    f = open('decrypted_' + file_name.decode('utf-8'), 'wb')
                    f.write(bytes(info))
                    f.write(bytes(d_data))
                    f.close()

                    print("Received file decrypt complete")
                    sock.send("Received file decrypt complete".encode('utf-8'))
                    print("Send : ", end='')
                    continue
        # print normal chatting
        else:
            print("\nReceived : ", rec_data.decode('utf-8'))
            print("Send : ", end='')


if __name__ == '__main__':
    RSA = RSA()

    e, d, n = RSA.keygen(2048)

    HOST = '127.0.0.1'
    PORT = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    print("Server Start")

    server_socket.listen(1)
    client_socket, address = server_socket.accept()

    print(address, "is connected")
    print("Type 'help' to read the command")
    print("Send : ", end='')

    sender = threading.Thread(target=send, args=(client_socket,))
    receiver = threading.Thread(target=receive, args=(client_socket,))

    sender.start()
    receiver.start()

    sender.join()
    receiver.join()

    client_socket.close()
    server_socket.close()
