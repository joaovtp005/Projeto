import socket
import threading
import json
import sqlite3
import time
import sys

HOST = '127.0.0.1'  
PORT = 65432        

def init_db():
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
   
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS offline_messages (
            recipient TEXT,
            sender TEXT,
            timestamp TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Banco de dados inicializado.")

def register_user(username, password):
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        print(f"Usuário {username} registrado com sucesso.")
        return True
    except sqlite3.IntegrityError:
        print(f"Falha no registro: Nome de usuário {username} já existe.")
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"Usuário {username} autenticado com sucesso.")
    else:
        print(f"Autenticação falhou para {username}.")
    return user is not None

def store_offline_message(recipient, sender, timestamp, message):
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO offline_messages (recipient, sender, timestamp, message) VALUES (?, ?, ?, ?)",
                       (recipient, sender, timestamp, message))
        conn.commit()
        print(f"Mensagem offline armazenada para {recipient} de {sender}.")
        return True
    except Exception as e:
        print(f"Erro ao armazenar mensagem offline: {e}")
        return False
    finally:
        conn.close()

def get_offline_messages(recipient):
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT sender, timestamp, message FROM offline_messages WHERE recipient = ?", (recipient,))
    messages = cursor.fetchall()
    
    cursor.execute("DELETE FROM offline_messages WHERE recipient = ?", (recipient,))
    conn.commit()
    conn.close()
    print(f"Recuperadas {len(messages)} mensagens offline para {recipient}.")
    return messages

def get_all_users():
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = [row[0] for row in cursor.fetchall()]
    conn.close()
    return users


online_users_lock = threading.Lock()
online_users = {} 
user_typing_status = {} 
def send_to_client(client_socket, message_dict):
    try:
        message_json = json.dumps(message_dict) + '\n' 
        client_socket.sendall(message_json.encode('utf-8'))
    except Exception as e:
        print(f"Erro ao enviar mensagem para o cliente: {e}")
        

def handle_client(conn, addr):
    print(f"Conectado por {addr}")
    current_user = None
    buffer = "" 

    try:
        while True:
            data = conn.recv(4096).decode('utf-8') 
            if not data:
                print(f"Cliente {addr} desconectou.")
                break
            
            buffer += data
           
            while '\n' in buffer:
                message_str, buffer = buffer.split('\n', 1)
                if not message_str.strip(): 
                    continue
                
                try:
                    message = json.loads(message_str)
                    msg_type = message.get('type')
                    print(f"Servidor recebeu de {addr}: {message_str}")

                    if msg_type == 'REGISTER':
                        username = message.get('username')
                        password = message.get('password')
                        if register_user(username, password):
                            send_to_client(conn, {'type': 'SUCCESS', 'message': 'Registro realizado com sucesso!'})
                        else:
                            send_to_client(conn, {'type': 'ERROR', 'message': 'Nome de usuário já em uso.'})
                        
                        break 

                    elif msg_type == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        if authenticate_user(username, password):
                            with online_users_lock:
                                if username in online_users:
                                    send_to_client(conn, {'type': 'ERROR', 'message': 'Usuário já logado.'})
                                    continue 
                                online_users[username] = conn
                                current_user = username
                            
                            print(f"Usuário {current_user} logado.")
                            send_to_client(conn, {'type': 'SUCCESS', 'message': 'Login realizado com sucesso!', 'username': current_user})
                            
                           
                            offline_msgs = get_offline_messages(current_user)
                            for sender, timestamp, msg_text in offline_msgs:
                                offline_msg_payload = {
                                    'type': 'MESSAGE',
                                    'sender': sender,
                                    'recipient': current_user,
                                    'timestamp': timestamp,
                                    'text': msg_text
                                }
                                send_to_client(conn, offline_msg_payload)
                            
                            
                            with online_users_lock:
                                for user, client_conn in online_users.items():
                                    if user != current_user:
                                        send_to_client(client_conn, {'type': 'STATUS', 'user': current_user, 'status': 'online'})
                        else:
                            send_to_client(conn, {'type': 'ERROR', 'message': 'Nome de usuário ou senha inválidos.'})

                    elif msg_type == 'GET_CONTACTS':
                        if current_user:
                            all_users = get_all_users()
                            send_to_client(conn, {'type': 'CONTACT_LIST', 'contacts': all_users})
                        else:
                            send_to_client(conn, {'type': 'ERROR', 'message': 'Não está logado.'})

                    elif msg_type == 'MESSAGE':
                        sender = message.get('sender')
                        recipient = message.get('recipient')
                        msg_text = message.get('text')
                        timestamp = message.get('timestamp')

                        with online_users_lock:
                            if recipient in online_users:
                                send_to_client(online_users[recipient], message) 
                                print(f"Mensagem de {sender} para {recipient} (online): {msg_text}")
                            else:
                                store_offline_message(recipient, sender, timestamp, msg_text)
                                send_to_client(conn, {'type': 'INFO', 'message': f'Destinatário {recipient} está offline. Mensagem armazenada.'})
                                print(f"Mensagem de {sender} para {recipient} (offline): {msg_text} - Armazenada.")

                    elif msg_type == 'TYPING':
                        sender = message.get('sender')
                        recipient = message.get('recipient')
                        is_typing = message.get('is_typing')
                        
                        
                        user_typing_status[sender] = {'recipient': recipient, 'is_typing': is_typing}
                        
                        with online_users_lock:
                            if recipient in online_users:
                                
                                send_to_client(online_users[recipient], {'type': 'TYPING_STATUS', 'user': sender, 'is_typing': is_typing})
                            print(f"Status de digitação de {sender} para {recipient}: {is_typing}")
                    
                    

                except json.JSONDecodeError:
                    print(f"JSON malformado recebido de {addr}: {message_str}")
                except Exception as e:
                    print(f"Erro ao processar mensagem de {addr}: {e}")
                   

    except ConnectionResetError:
        print(f"Cliente {addr} desconectou-se forçosamente.")
    except Exception as e:
        print(f"Erro inesperado com o cliente {addr}: {e}")
    finally:
        
        if current_user:
            with online_users_lock:
                if current_user in online_users:
                    del online_users[current_user]
                    print(f"Usuário {current_user} desconectado. Total online: {len(online_users)}")
                    
                    for user, client_conn in online_users.items():
                        send_to_client(client_conn, {'type': 'STATUS', 'user': current_user, 'status': 'offline'})
        conn.close()
        print(f"Conexão de {addr} fechada.")


def start_server():
    init_db()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) 
        print(f"Servidor escutando em {HOST}:{PORT}")
    except Exception as e:
        print(f"Falha ao iniciar o servidor: {e}")
        sys.exit(1) 

    while True:
        try:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True 
            client_thread.start()
        except KeyboardInterrupt:
            print("Servidor desligando...")
            break
        except Exception as e:
            print(f"Erro ao aceitar conexão: {e}")

    server_socket.close()

if __name__ == '__main__':
    start_server()