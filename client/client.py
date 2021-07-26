import socket
import threading
from AES_RSA.AES import AES
from AES_RSA.RSA import RSA

encrypted_key = [
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0
]
rsa_key = False
aes_key = False


# Socket Send function
def send(sock):
    global aes_key
    while True:
        sen_data = input()

        # print available command
        if sen_data == "help":
            print("1. encrypted_aes_key")
            print("\tSend encrypted AES key to Server")
            print("2. ----.bmp")
            print("\tSend encrypted ---.bmp file to Server")
            print("3. quit")
            print("\tQuit Client")
            print("Send : ", end='')
            continue
        # send encrypted AES key
        elif sen_data == "encrypted_aes_key":
            # if RSA encrypt(public) key does not exist
            if not rsa_key:
                print("Need RSA encrypt")
                print("Send : ", end='')
            # RSA encrypt(public) key exists
            else:
                # Send AES key
                aes_key = True

                print("Encrypted AES key sending")
                sock.send("encrypted_aes_key".encode('utf-8'))
                for i in range(16):
                    key_len = len(str(encrypted_key[i]))
                    sock.send(str(key_len).encode('utf-8'))
                    sock.send(str(encrypted_key[i]).encode('utf-8'))
                print("\nSend encrypted AES key")
                print("Send : ", end='')
            continue

        sock.send(sen_data.encode('utf-8'))

        # quit Client
        if "quit" in sen_data:
            print("Quit Client")
            exit()
        # send encrypted data
        # Server need AES key
        if ".bmp" in sen_data:
            # if server does not have AES key
            if not aes_key:
                print("Need AES key")
            # server has AES key
            else:
                print("AES key exists")
                print("Decrypting file")
                try:
                    # file open
                    f = open(sen_data, 'rb')
                    bmp = f.read()
                    f.close()

                    # encrypt file
                    bmp_hex = list(bmp)
                    e_info = bmp_hex[:bmp_hex[10]]
                    e_data = bmp_hex[bmp_hex[10]:]
                    e_info, e_data = AES.aes_data_encrypt(e_info, e_data)

                    # store encrypted file
                    enc_file = "encrypt_" + sen_data
                    f = open(enc_file, 'wb')
                    f.write(bytes(e_info))
                    f.write(bytes(e_data))
                    f.close()

                    # "1" means enc_file exists
                    sock.send("1".encode('utf-8'))
                    # send file info(header), data size
                    sock.send(str(len(e_info)).encode('utf-8'))
                    sock.send(str(len(e_data)).encode('utf-8'))

                    # send file info(header)
                    for i in range(len(e_info)):
                        e_info[i] = str(e_info[i])
                        sock.send(str(len(e_info[i])).encode('utf-8'))
                        sock.send(e_info[i].encode('utf-8'))
                    # send file data
                    for i in range(len(e_data)):
                        e_data[i] = str(e_data[i])
                        sock.send(str(len(e_data[i])).encode('utf-8'))
                        sock.send(e_data[i].encode('utf-8'))

                    print("Send " + sen_data + " file complete")
                except FileNotFoundError:
                    print("No exists file")
                    # "0" means enc_file does not exist
                    sock.send("0".encode('utf-8'))

        print("Send : ", end='')


# Socket Receive function
def receive(sock):
    while True:
        rec_data = sock.recv(1024)

        # Server is closed
        if "quit" in rec_data.decode('utf-8'):
            print("\nServer Closed")
            sock.send(rec_data)
            exit()
        # Receive RSA encrypt(public) key
        elif rec_data.decode('utf-8') == "rsa_encrypt_key":
            global rsa_key
            rsa_key = True
            print("\nReceive RSA encrypt key")
            print("Client Key Encrypting")

            # receive RSA e, n
            e_len = sock.recv(4)
            n_len = sock.recv(4)
            e = sock.recv(int(e_len.decode('utf-8')))
            n = sock.recv(int(n_len.decode('utf-8')))
            e = int(e.decode('utf-8'))
            n = int(n.decode('utf-8'))

            # Encrypt AES keys using RSA encrypt(public) key
            for i in range(16):
                encrypted_key[i] = RSA.encrypt(AES.key[i], e, n)
            print("Key Encrypted")
            sock.send("Key Encrypted".encode('utf-8'))
            print("Send : ", end='')
            continue
        # print normal chatting
        else:
            print("\nReceived : ", rec_data.decode('utf-8'))
            print("Send : ", end='')


if __name__ == '__main__':
    AES = AES()
    RSA = RSA()

    HOST = '127.0.0.1'
    PORT = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Client Start")

    try:
        client_socket.connect((HOST, PORT))

        print("Server Connected")
        print("Type 'help' to read the command")
        print("Send : ", end='')

        sender = threading.Thread(target=send, args=(client_socket,))
        receiver = threading.Thread(target=receive, args=(client_socket,))

        sender.daemon = True
        receiver.daemon = True

        sender.start()
        receiver.start()

        sender.join()
        receiver.join()

        client_socket.close()
    # Server not yet Start
    except ConnectionRefusedError:
        print("You can't access the Server. Please re-run program")
