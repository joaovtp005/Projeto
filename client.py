import socket
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time
import sys

HOST = '127.0.0.1' 
PORT = 65432

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Cliente de Chat")
        master.geometry("600x500")
        master.protocol("WM_DELETE_WINDOW", self.on_closing) 

        self.username = None
        self.socket = None
        self.receive_thread = None
        self.is_connected = False
        self.recipient_chat_window = None 

        
        self.contacts_status = {} 

        
        self.status_label = tk.Label(self.master, text="Offline", fg="red")
        self.status_label.pack(side=tk.BOTTOM, anchor=tk.E, padx=5, pady=5)

        self.create_login_gui()

        
        self.typing_timer = None
        self.is_typing_event_sent = False

    def create_login_gui(self):
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Nome de Usuário:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.login_frame, text="Senha:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(self.login_frame, text="Login", command=self.attempt_login).grid(row=2, column=0, pady=10)
        tk.Button(self.login_frame, text="Registrar", command=self.attempt_register).grid(row=2, column=1, pady=10)

    def create_chat_gui(self):
        
        if hasattr(self, 'login_frame') and self.login_frame.winfo_exists():
            self.login_frame.destroy()

        self.main_frame = tk.Frame(self.master)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        
        self.contact_list_frame = tk.Frame(self.main_frame, width=150, bd=2, relief=tk.GROOVE)
        self.contact_list_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        tk.Label(self.contact_list_frame, text="Contatos").pack(pady=5)
        self.contact_listbox = tk.Listbox(self.contact_list_frame)
        self.contact_listbox.pack(fill=tk.BOTH, expand=True)
        self.contact_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        # Janela de Chat
        self.chat_frame = tk.Frame(self.main_frame, bd=2, relief=tk.GROOVE)
        self.chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state='disabled')
        self.chat_display.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.typing_indicator_label = tk.Label(self.chat_frame, text="", fg="gray")
        self.typing_indicator_label.pack(anchor=tk.W, padx=5)

        self.message_entry = tk.Entry(self.chat_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        self.message_entry.bind('<Key>', self.on_key_press_message_entry) 
        self.message_entry.bind('<Return>', self.send_message_event) 

        tk.Button(self.chat_frame, text="Enviar", command=self.send_message).pack(side=tk.RIGHT, padx=5, pady=5)

         

    def connect_to_server(self):
        if self.is_connected and self.socket: 
            return True
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            self.is_connected = True
           
            self.master.after(0, lambda: self.status_label.config(text="Online", fg="green"))
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True  
            self.receive_thread.start()
            return True
        except ConnectionRefusedError:
            self.master.after(0, lambda: messagebox.showerror("Erro de Conexão", "Não foi possível conectar ao servidor. Ele está rodando?"))
            self.is_connected = False
            self.master.after(0, lambda: self.status_label.config(text="Offline", fg="red"))
            return False
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Erro de Conexão", f"Ocorreu um erro durante a conexão: {e}"))
            self.is_connected = False
            self.master.after(0, lambda: self.status_label.config(text="Offline", fg="red"))
            return False

    def send_data(self, data):
        if not self.is_connected or not self.socket:
            self.master.after(0, lambda: messagebox.showwarning("Não Conectado", "Por favor, conecte-se ao servidor primeiro."))
            return False
        try:
            message_json = json.dumps(data) + '\n' 
            self.socket.sendall(message_json.encode('utf-8'))
            return True
        except Exception as e:
            print(f"Erro ao enviar dados: {e}")
            self.master.after(0, self.disconnect) 
            self.master.after(0, lambda: messagebox.showerror("Erro de Conexão", "Desconectado do servidor. Por favor, tente fazer login novamente."))
            return False

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.master.after(0, lambda: messagebox.showwarning("Erro de Entrada", "Por favor, insira nome de usuário e senha."))
            return

        if not self.connect_to_server(): 
            return

        login_payload = {
            'type': 'LOGIN',
            'username': username,
            'password': password
        }
        self.send_data(login_payload)
       

    def attempt_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.master.after(0, lambda: messagebox.showwarning("Erro de Entrada", "Por favor, insira nome de usuário e senha."))
            return

        if not self.connect_to_server(): 
            return

        register_payload = {
            'type': 'REGISTER',
            'username': username,
            'password': password
        }
       
        self.send_data(register_payload)
        

    def receive_messages(self):
        buffer = ""
        while self.is_connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    print("Servidor desconectado.")
                    self.master.after(0, self.disconnect) 
                    break
                
                buffer += data
                while '\n' in buffer:
                    message_str, buffer = buffer.split('\n', 1)
                    if not message_str.strip():
                        continue
                    
                    try:
                        message = json.loads(message_str)
                        msg_type = message.get('type')
                        print(f"Cliente recebeu: {message_str}")

                        if msg_type == 'SUCCESS':
                            if message.get('username'): 
                                self.username = message['username']
                                self.master.after(0, lambda: messagebox.showinfo("Sucesso", message['message']))
                                self.master.after(0, self.create_chat_gui)
                                self.master.after(0, self.request_contact_list) 
                            else: 
                                self.master.after(0, lambda: messagebox.showinfo("Sucesso", message['message']))
                                
                                self.master.after(0, self.disconnect) 
                                self.master.after(0, self.reset_to_login_gui)

                        elif msg_type == 'ERROR':
                            self.master.after(0, lambda: messagebox.showerror("Erro", message['message']))
                            if message['message'] == 'Usuário já logado.' or \
                               message['message'] == 'Nome de usuário ou senha inválidos.':
                                self.master.after(0, self.disconnect) 
                                self.master.after(0, self.reset_to_login_gui)

                        elif msg_type == 'INFO':
                            self.master.after(0, lambda: self.display_message(f"[INFO] {message['message']}"))

                        elif msg_type == 'MESSAGE':
                            sender = message.get('sender')
                            text = message.get('text')
                            timestamp = message.get('timestamp')
                           
                            if self.recipient_chat_window == sender or self.recipient_chat_window == message.get('recipient') or message.get('recipient') == self.username:
                                self.master.after(0, lambda: self.display_message(f"[{timestamp}] {sender}: {text}"))

                        elif msg_type == 'CONTACT_LIST':
                            contacts = message.get('contacts', [])
                            self.master.after(0, lambda: self.update_contact_list(contacts)) 

                        elif msg_type == 'TYPING_STATUS':
                            user = message.get('user')
                            is_typing = message.get('is_typing')
                            if self.recipient_chat_window == user:
                                self.master.after(0, lambda: self.show_typing_indicator(user, is_typing))
                        
                        elif msg_type == 'STATUS': 
                            user = message.get('user')
                            status = message.get('status')
                            self.master.after(0, lambda: self.update_contact_status(user, status))

                    except json.JSONDecodeError:
                        print(f"JSON malformado recebido do servidor: {message_str}")
                    
            except ConnectionResetError:
                print("Servidor fechou a conexão inesperadamente.")
                self.master.after(0, self.disconnect) 
                self.master.after(0, self.reset_to_login_gui)
                break
            except Exception as e:
                print(f"Erro em receive_messages: {e}")
                self.master.after(0, self.disconnect) 
                self.master.after(0, self.reset_to_login_gui)
                break

    def display_message(self, message):
       
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.yview(tk.END)
        self.chat_display.config(state='disabled')

    def send_message_event(self, event=None):
        self.send_message()

    def send_message(self):
        if not self.recipient_chat_window:
            self.master.after(0, lambda: messagebox.showwarning("Sem Destinatário", "Por favor, selecione um contato para conversar."))
            return

        message_text = self.message_entry.get()
        if message_text.strip():
            timestamp = time.strftime('%H:%M:%S')
            message_payload = {
                'type': 'MESSAGE',
                'sender': self.username,
                'recipient': self.recipient_chat_window,
                'timestamp': timestamp,
                'text': message_text
            }
            if self.send_data(message_payload):
                self.display_message(f"[{timestamp}] Você: {message_text}")
                self.master.after(0, lambda: self.message_entry.delete(0, tk.END)) 
                self.send_typing_status(False) 
                self.is_typing_event_sent = False 

    def on_key_press_message_entry(self, event):
        if self.recipient_chat_window and self.username:
            if not self.is_typing_event_sent: 
                self.send_typing_status(True)
                self.is_typing_event_sent = True
            
           
            if self.typing_timer:
                self.master.after_cancel(self.typing_timer)
            self.typing_timer = self.master.after(2000, self.send_stop_typing_status) 

    def send_stop_typing_status(self):
        if self.is_typing_event_sent:
            self.send_typing_status(False)
            self.is_typing_event_sent = False

    def send_typing_status(self, is_typing):
        if self.recipient_chat_window and self.username:
            typing_payload = {
                'type': 'TYPING',
                'sender': self.username,
                'recipient': self.recipient_chat_window,
                'is_typing': is_typing
            }
            self.send_data(typing_payload)

    def show_typing_indicator(self, user, is_typing):
       
        if is_typing:
            self.typing_indicator_label.config(text=f"{user} está digitando...")
        else:
            self.typing_indicator_label.config(text="")

    def request_contact_list(self):
       
        if self.username:
            contact_request_payload = {
                'type': 'GET_CONTACTS',
                'username': self.username
            }
            self.send_data(contact_request_payload)

    def update_contact_list(self, contacts):
        
        self.contact_listbox.delete(0, tk.END)
        
        for contact in sorted(contacts): 
            if contact != self.username:
                self.contact_listbox.insert(tk.END, contact)
        
    def on_contact_select(self, event):
        selected_indices = self.contact_listbox.curselection()
        if selected_indices:
            new_recipient = self.contact_listbox.get(selected_indices[0])
            if new_recipient != self.recipient_chat_window: 
                self.recipient_chat_window = new_recipient
                self.display_message(f"--- Conversando com {self.recipient_chat_window} ---")
                self.chat_display.config(state='normal')
                self.chat_display.delete('1.0', tk.END) 
                self.chat_display.config(state='disabled')
                self.typing_indicator_label.config(text="") 

    def update_contact_status(self, user, status):
        print(f"Usuário {user} está agora {status}")
        

    def reset_to_login_gui(self):

        if hasattr(self, 'main_frame') and self.main_frame.winfo_exists():
            self.main_frame.destroy()
        
        self.username = None
        self.recipient_chat_window = None
        self.is_typing_event_sent = False
        if self.typing_timer:
            self.master.after_cancel(self.typing_timer)
            self.typing_timer = None

        self.create_login_gui()
        self.status_label.config(text="Offline", fg="red")

    def disconnect(self):
        
        if self.is_connected: 
            self.is_connected = False
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR) 
                    self.socket.close()
                except OSError as e:
                    print(f"Erro durante o desligamento/fechamento do socket: {e}")
                finally:
                    self.socket = None
            
            self.master.after(0, lambda: self.status_label.config(text="Offline", fg="red"))
            print("Cliente desconectado.")
       

    def on_closing(self):
        if messagebox.askokcancel("Sair", "Deseja realmente sair?"):
            self.disconnect() 
            self.master.destroy()
            sys.exit(0) 

def main():
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()

if __name__ == '__main__':
    main()