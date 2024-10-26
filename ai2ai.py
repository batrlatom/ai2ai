import socket
import threading
import json
import time
import uuid
import os
import logging
import ssl
from dataclasses import dataclass, asdict
from typing import Dict, Optional, List
from collections import defaultdict
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key, 
    PrivateFormat, NoEncryption
)
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidKey
import base64
import sys
import jsonschema

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('p2p_network.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


REGISTER_MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["register"]},
        "peer_id": {
            "type": "string", 
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        },
        "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
        "server_port": {"type": "integer", "minimum": 1024, "maximum": 65535},
        "public_key": {"type": "string"},
        "signature": {"type": "string"}
    },
    "required": ["type", "peer_id", "port", "public_key", "signature"],
    "additionalProperties": False
}

PEERS_MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["peers"]},
        "peers": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "last_seen": {"type": "number"},
                    "public_key": {"type": "string"},
                    "nat_type": {"type": "string"}
                },
                "required": ["id", "host", "port", "last_seen", "public_key"]
            }
        }
    },
    "required": ["type", "peers"],
    "additionalProperties": False
}

MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["message"]},
        "peer_id": {
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        },
        "content": {"type": "string"},
        "signature": {"type": "string"},
        "timestamp": {"type": "number"}
    },
    "required": ["type", "peer_id", "content", "signature", "timestamp"],
    "additionalProperties": False
}

ERROR_MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["error"]},
        "message": {"type": "string"}
    },
    "required": ["type", "message"],
    "additionalProperties": False
}

@dataclass
class Peer:
    id: str
    host: str
    port: int
    last_seen: float
    public_key: str
    nat_type: str = "unknown"



class RateLimiter:
    def __init__(self, max_requests: int, time_window: float):
        """Initialize the rate limiter.
        
        Args:
            max_requests (int): Maximum number of requests allowed within the time window
            time_window (float): Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        """Check if a client is allowed to make a request.
        
        Args:
            client_id (str): Unique identifier for the client
            
        Returns:
            bool: True if request is allowed, False otherwise
        """
        now = time.time()
        
        # Remove expired timestamps
        self.requests[client_id] = [
            timestamp 
            for timestamp in self.requests[client_id] 
            if now - timestamp < self.time_window
        ]
        
        # Check if client exceeded rate limit
        if len(self.requests[client_id]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for client {client_id}")
            return False
            
        # Add new request timestamp
        self.requests[client_id].append(now)
        return True

    def clear_old_entries(self):
        """Clear expired entries from the requests dictionary."""
        now = time.time()
        for client_id in list(self.requests.keys()):
            self.requests[client_id] = [
                timestamp 
                for timestamp in self.requests[client_id] 
                if now - timestamp < self.time_window
            ]
            if not self.requests[client_id]:
                del self.requests[client_id]

class SecurityManager:
    def __init__(self, password: str):
        # Use a fixed salt for network-wide consistency
        self.salt = b'p2pnetworksalt1234'  # Fixed salt for all peers
        self.key = self._derive_key(password)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # Initialize Fernet with the network-wide key
        key_bytes = base64.urlsafe_b64encode(self.key)
        self.fernet = Fernet(key_bytes)

    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: bytes) -> bytes:
        try:
            return self.fernet.encrypt(data)
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self.fernet.decrypt(data)
        except InvalidKey as e:
            logger.error("Invalid decryption key")
            raise
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise

    def sign(self, data: bytes) -> bytes:
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature)

    def verify_signature(self, public_key_pem: str, data: bytes, signature: bytes) -> bool:
        try:
            public_key = load_pem_public_key(public_key_pem.encode())
            public_key.verify(
                base64.b64decode(signature),
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode()



class SecureServer:
    def __init__(
        self, 
        host: str = '0.0.0.0', 
        port: int = 55555, 
        cert_path: str = 'server.crt', 
        key_path: str = 'server.key', 
        password: str = 'server_default_password'
    ):
        """Initialize the secure server."""
        self.host = host
        self.port = port
        self.peers: Dict[str, Peer] = {}
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60.0)
        
        # Initialize security manager
        self.security_manager = SecurityManager(password)
        
        # Setup SSL context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except Exception as e:
            logger.error(f"Failed to load certificates: {e}")
            raise
        
        # Create socket with SSL wrapper
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.ssl_socket = self.ssl_context.wrap_socket(self.socket, server_side=True)
            logger.info(f"Server started on {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

        self.running = True

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_inactive_peers)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def _cleanup_inactive_peers(self):
        """Remove inactive peers periodically."""
        while self.running:
            try:
                current_time = time.time()
                inactive_peers = [
                    peer_id for peer_id, peer in self.peers.items()
                    if current_time - peer.last_seen > 300  # 5 minutes timeout
                ]
                for peer_id in inactive_peers:
                    del self.peers[peer_id]
                    logger.info(f"Removed inactive peer: {peer_id}")
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")
                time.sleep(60)  # Wait before retrying

    def start(self):
        """Start the server and accept incoming connections."""
        logger.info("[+] Waiting for connections...")
        
        while self.running:
            try:
                client, addr = self.ssl_socket.accept()
                logger.info(f"[+] New connection from {addr[0]}:{addr[1]}")
                
                client_handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                
            except KeyboardInterrupt:
                logger.info("\n[+] Shutting down server...")
                break
            except ssl.SSLError as e:
                logger.error(f"SSL error: {e}")
                continue
            except Exception as e:
                logger.error(f"Server error: {e}")
                continue
        
        self.shutdown()

  

    def _handle_client(self, client: ssl.SSLSocket, addr: tuple) -> None:
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            if not self.rate_limiter.is_allowed(client_id):
                logger.warning(f"Rate limit exceeded for {client_id}")
                return

            data = client.recv(4096)
            if not data:
                return
                
            try:
                msg = json.loads(data.decode())
                
                if msg['type'] == 'register':
                    # Validate message schema
                    jsonschema.validate(instance=msg, schema=REGISTER_MESSAGE_SCHEMA)
                    
                    # Verify signature
                    if not self.security_manager.verify_signature(
                        msg['public_key'],
                        json.dumps({k: v for k, v in msg.items() if k != 'signature'}).encode(),
                        msg['signature'].encode()
                    ):
                        error_response = {
                            'type': 'error',
                            'message': 'Invalid signature'
                        }
                        client.send(json.dumps(error_response).encode())
                        return
                    
                    peer = Peer(
                        id=msg['peer_id'],
                        host=addr[0],
                        port=msg['port'],  # This is the p2p_port for UDP communication
                        last_seen=time.time(),
                        public_key=msg['public_key']
                    )
                    self.peers[msg['peer_id']] = peer
                    logger.info(f"New peer registered: {peer.id} ({peer.host}:{peer.port})")
                    
                    # Debug print current peers
                    logger.info("Current peer list:")
                    for pid, p in self.peers.items():
                        logger.info(f"  - Peer {pid}: {p.host}:{p.port}")
                    
                    # Send initial peer list to the new peer over TCP
                    response = {
                        'type': 'peers',
                        'peers': [asdict(p) for p in self.peers.values()]
                    }
                    response_data = json.dumps(response).encode()
                    client.send(response_data)
                    
                    # Broadcast updated peer list to all other peers using UDP
                    self._broadcast_peer_list(exclude_peer_id=msg['peer_id'])
                    
            except jsonschema.ValidationError as e:
                logger.error(f"Invalid message format from {client_id}: {e}")
                error_response = {
                    'type': 'error',
                    'message': 'Invalid message format'
                }
                client.send(json.dumps(error_response).encode())
                return
            except Exception as e:
                logger.error(f"Error processing message from {client_id}: {e}")
                error_response = {
                    'type': 'error',
                    'message': 'Internal server error'
                }
                client.send(json.dumps(error_response).encode())
                return
                
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def _broadcast_peer_list(self, exclude_peer_id: Optional[str] = None):
        """Send updated peer list to all connected peers except the excluded one."""
        try:
            response = {
                'type': 'peers',
                'peers': [asdict(p) for p in self.peers.values()]
            }
            response_data = json.dumps(response).encode()
            
            # Create a UDP socket for broadcasting
            broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send to each peer using UDP
            for peer in self.peers.values():
                if exclude_peer_id and peer.id == exclude_peer_id:
                    continue
                    
                try:
                    logger.info(f"Broadcasting peer list to {peer.id} at {peer.host}:{peer.port}")
                    broadcast_socket.sendto(response_data, (peer.host, peer.port))
                except Exception as e:
                    logger.error(f"Failed to send peer list to {peer.id}: {e}")
            
            broadcast_socket.close()
            
        except Exception as e:
            logger.error(f"Error broadcasting peer list: {e}")


    # Update in the SecureNode class
    def _listen_for_server(self):
        """Listen for peer list updates from the server."""
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                try:
                    data = client.recv(4096)
                    if data:
                        msg = json.loads(data.decode())
                        if msg['type'] == 'peers':
                            jsonschema.validate(instance=msg, schema=PEERS_MESSAGE_SCHEMA)
                            new_peers = {}
                            for peer_data in msg['peers']:
                                if peer_data['id'] != self.peer_id:  # Don't add self
                                    new_peers[peer_data['id']] = Peer(**peer_data)
                            
                            # Update peers dictionary
                            self.peers = new_peers
                            logger.info(f"Updated peer list, found {len(self.peers)} peers")
                            for peer_id in self.peers:
                                logger.info(f"  - Peer: {peer_id}")
                except Exception as e:
                    logger.error(f"Error processing server update: {e}")
                finally:
                    client.close()
            except Exception as e:
                if self.running:
                    logger.error(f"Error in server listener: {e}")



    def shutdown(self):
        """Gracefully shutdown the server."""
        logger.info("Shutting down server...")
        self.running = False
        try:
            self.ssl_socket.close()
            self.socket.close()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

class SecureNode:
    def __init__(self, rendezvous_server: str, rendezvous_port: int, network_password: str,
                 cert_path: str = 'server.crt'):
        self.peer_id = str(uuid.uuid4())
        self.peers: Dict[str, Peer] = {}
        self.rendezvous_server = rendezvous_server
        self.rendezvous_port = rendezvous_port
        
        # Security setup
        self.security_manager = SecurityManager(network_password)
        
        # Setup SSL context for server connection
        self.ssl_context = ssl.create_default_context()
        try:
            self.ssl_context.load_verify_locations(cert_path)
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            sys.exit(1)
        
        # Setup UDP socket for P2P communication
        self.p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.p2p_socket.bind(('0.0.0.0', 0))
        self.p2p_port = self.p2p_socket.getsockname()[1]
        
        # Setup TCP socket for server updates
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 0))
        self.server_socket.listen(5)
        self.server_port = self.server_socket.getsockname()[1]
        
        self.running = True
        self.rate_limiter = RateLimiter(max_requests=50, time_window=60.0)
        
        logger.info(f"Node started with ID {self.peer_id}")
        logger.info(f"P2P port: {self.p2p_port}, Server port: {self.server_port}")

        # Start threads
        self.listener_thread = threading.Thread(target=self._listen_for_peers)
        self.listener_thread.daemon = True
        self.listener_thread.start()

        self.cleanup_thread = threading.Thread(target=self._cleanup_inactive_peers)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        self.server_thread = threading.Thread(target=self._listen_for_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def _listen_for_server(self):
        """Listen for peer list updates from the server."""
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                try:
                    data = client.recv(4096)
                    if data:
                        msg = json.loads(data.decode())
                        if msg['type'] == 'peers':
                            jsonschema.validate(instance=msg, schema=PEERS_MESSAGE_SCHEMA)
                            
                            # Update peers dictionary with proper port information
                            new_peers = {}
                            for peer_data in msg['peers']:
                                if peer_data['id'] != self.peer_id:  # Don't add self
                                    logger.info(f"Updating peer list with: {peer_data['id']} on port {peer_data['port']}")
                                    new_peers[peer_data['id']] = Peer(**peer_data)
                            
                            # Update peers dictionary
                            self.peers = new_peers
                            logger.info(f"Updated peer list, found {len(self.peers)} peers")
                            self._debug_print_peers()  # Debug print peers
                            
                except Exception as e:
                    logger.error(f"Error processing server update: {e}")
                finally:
                    client.close()
            except Exception as e:
                if self.running:
                    logger.error(f"Error in server listener: {e}")

    def _debug_print_peers(self):
        """Debug method to print current peers"""
        logger.info("Current peers:")
        for peer_id, peer in self.peers.items():
            logger.info(f"  - Peer {peer_id}: {peer.host}:{peer.port}")

    def connect(self) -> bool:
        try:
            logger.info(f"Connecting to server {self.rendezvous_server}:{self.rendezvous_port}")
            with socket.create_connection((self.rendezvous_server, self.rendezvous_port)) as sock:
                with self.ssl_context.wrap_socket(sock, server_hostname=self.rendezvous_server) as ssl_sock:
                    ssl_sock.settimeout(10)
                    
                    msg_data = {
                        'type': 'register',
                        'peer_id': self.peer_id,
                        'port': self.p2p_port,  # Use P2P port for peer communication
                        'server_port': self.server_port,  # Include server port for updates
                        'public_key': self.security_manager.get_public_key_pem()
                    }
                    
                    signature = self.security_manager.sign(
                        json.dumps({k: v for k, v in msg_data.items() if k != 'signature'}).encode()
                    )
                    msg_data['signature'] = signature.decode()
                    
                    ssl_sock.send(json.dumps(msg_data).encode())
                    
                    data = ssl_sock.recv(4096)
                    if not data:
                        raise Exception("No response from server")
                        
                    response = json.loads(data.decode())
                    if response['type'] == 'peers':
                        jsonschema.validate(instance=response, schema=PEERS_MESSAGE_SCHEMA)
                        for peer_data in response['peers']:
                            if peer_data['id'] != self.peer_id:
                                self.peers[peer_data['id']] = Peer(**peer_data)
                                logger.info(f"Discovered peer: {peer_data['id']} on port {peer_data['port']}")
                        
                        self._debug_print_peers()  # Debug print peers after connection
                                
            logger.info("Successfully connected to network")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def _listen_for_peers(self):
        """Listen for peer messages."""
        logger.info(f"Starting peer listener on port {self.p2p_port}")
        while self.running:
            try:
                data, addr = self.p2p_socket.recvfrom(4096)
                peer_addr = f"{addr[0]}:{addr[1]}"
                
                logger.debug(f"Received data from {peer_addr}")
                
                if not self.rate_limiter.is_allowed(peer_addr):
                    continue
                
                try:
                    msg = json.loads(data.decode())
                    if msg['type'] == 'message':
                        # Verify peer and signature
                        peer = self.peers.get(msg['peer_id'])
                        if not peer:
                            logger.warning(f"Message from unknown peer: {msg['peer_id']}")
                            self._debug_print_peers()
                            continue
                        
                        if not self.security_manager.verify_signature(
                            peer.public_key,
                            json.dumps({k: v for k, v in msg.items() if k != 'signature'}).encode(),
                            msg['signature'].encode()
                        ):
                            logger.warning(f"Invalid signature from peer: {msg['peer_id']}")
                            continue
                        
                        # Decrypt message
                        try:
                            encrypted_content = base64.b64decode(msg['content'])
                            decrypted_content = self.security_manager.decrypt(encrypted_content)
                            content = decrypted_content.decode()
                            
                            logger.info(f"Received message from {msg['peer_id']}: {content}")
                            print(f"\n[>] From {msg['peer_id']}: {content}")
                            print("Enter message (or 'quit' to exit): ", end='', flush=True)
                        except Exception as e:
                            logger.error(f"Failed to decrypt message: {str(e)}")
                            continue
                        
                    elif msg['type'] == 'peers':
                        # Handle peer list updates
                        jsonschema.validate(instance=msg, schema=PEERS_MESSAGE_SCHEMA)
                        new_peers = {}
                        for peer_data in msg['peers']:
                            if peer_data['id'] != self.peer_id:
                                new_peers[peer_data['id']] = Peer(**peer_data)
                                logger.info(f"Updated peer: {peer_data['id']} on port {peer_data['port']}")
                        
                        self.peers = new_peers
                        logger.info(f"Updated peer list, found {len(self.peers)} peers")
                        self._debug_print_peers()
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from {peer_addr}: {e}")
                except Exception as e:
                    logger.error(f"Error processing message from {peer_addr}: {e}")
                    continue
                    
            except Exception as e:
                if self.running:
                    logger.error(f"Listener error: {e}")
                continue

    def send_message(self, content: str):
        """Send a message to all peers."""
        if not self.peers:
            logger.warning("No peers connected")
            print("\nNo peers connected. Waiting for peer connections...")
            print("Enter message (or 'quit' to exit): ", end='', flush=True)
            return
            
        try:
            # Encrypt content
            encrypted = self.security_manager.encrypt(content.encode())
            
            # Prepare message
            msg_data = {
                'type': 'message',
                'peer_id': self.peer_id,
                'content': base64.b64encode(encrypted).decode(),
                'timestamp': time.time()
            }
            
            # Sign message
            signature = self.security_manager.sign(
                json.dumps({k: v for k, v in msg_data.items() if k != 'signature'}).encode()
            )
            msg_data['signature'] = signature.decode()
            
            # Send to all peers
            msg_bytes = json.dumps(msg_data).encode()
            successful_sends = 0
            logger.info("Attempting to send message to peers:")
            for peer in self.peers.values():
                try:
                    logger.info(f"  Sending to peer {peer.id} at {peer.host}:{peer.port}")
                    self.p2p_socket.sendto(msg_bytes, (peer.host, peer.port))
                    successful_sends += 1
                except Exception as e:
                    logger.error(f"Failed to send to {peer.id}: {e}")
            
            if successful_sends > 0:
                logger.info(f"Message sent to {successful_sends} peers")
            else:
                logger.warning("Failed to send message to any peers")
                print("\nFailed to send message to any peers")
                print("Enter message (or 'quit' to exit): ", end='', flush=True)
                
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            logger.error("Error details:", exc_info=True)  # Add full traceback
            print("\nFailed to send message")
            print("Enter message (or 'quit' to exit): ", end='', flush=True)

    def shutdown(self):
        logger.info("Shutting down...")
        self.running = False
        self.p2p_socket.close()
        self.server_socket.close()
        logger.info("Shutdown complete")            

    def _cleanup_inactive_peers(self):
        """Remove inactive peers periodically."""
        while self.running:
            try:
                current_time = time.time()
                inactive_peers = [
                    peer_id for peer_id, peer in self.peers.items()
                    if current_time - peer.last_seen > 300  # 5 minutes timeout
                ]
                for peer_id in inactive_peers:
                    del self.peers[peer_id]
                    logger.info(f"Removed inactive peer: {peer_id}")
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")
                time.sleep(60)  # Wait before retrying

    def start(self):
        """Start the server and accept incoming connections."""
        logger.info("[+] Waiting for connections...")
        
        while self.running:
            try:
                client, addr = self.ssl_socket.accept()
                logger.info(f"[+] New connection from {addr[0]}:{addr[1]}")
                
                client_handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                
            except KeyboardInterrupt:
                logger.info("\n[+] Shutting down server...")
                break
            except ssl.SSLError as e:
                logger.error(f"SSL error: {e}")
                continue
            except Exception as e:
                logger.error(f"Server error: {e}")
                continue
        
        self.shutdown()


def generate_certificates(host: str):
    """Generate self-signed certificates for testing"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host),
            x509.DNSName('localhost'),  # Add localhost for testing
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))  # Add localhost IP
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Save certificate
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    
    # Save private key
    with open("server.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

if __name__ == "__main__":
    import argparse
    import ipaddress
    
    parser = argparse.ArgumentParser(description='Secure P2P Network')
    parser.add_argument('role', choices=['server', 'node'],
                       help='Run as server or node')
    parser.add_argument('--host', default='localhost',
                       help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=55555,
                       help='Server port (default: 55555)')
    parser.add_argument('--password', default='defaultnetworkpassword',
                       help='Network password for encryption')
    parser.add_argument('--generate-certs', action='store_true',
                       help='Generate self-signed certificates')
    parser.add_argument('--cert-path', default='server.crt',
                       help='Path to server certificate')
    parser.add_argument('--key-path', default='server.key',
                       help='Path to server private key')
    
    args = parser.parse_args()
    
    try:
        if args.generate_certs:
            generate_certificates(args.host)
            logger.info("Generated self-signed certificates")
            
        if args.role == 'server':
            server = SecureServer(
                host=args.host,
                port=args.port,
                cert_path=args.cert_path,
                key_path=args.key_path,
                password=args.password
            )
            try:
                server.start()
            except KeyboardInterrupt:
                server.shutdown()
        else:
            node = SecureNode(
                rendezvous_server=args.host,
                rendezvous_port=args.port,
                network_password=args.password,
                cert_path=args.cert_path
            )
            if node.connect():
                try:
                    while True:
                        msg = input("Enter message (or 'quit' to exit): ")
                        if msg.lower() == 'quit':
                            break
                        node.send_message(msg)
                except KeyboardInterrupt:
                    pass
                finally:
                    node.shutdown()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
