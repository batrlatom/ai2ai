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

import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from enum import Enum
import time
import uuid


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

# Additional message schemas for marketplace functionality
TASK_MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["task"]},
        "action": {"type": "string", "enum": ["create", "bid", "assign", "submit", "validate"]},
        "task_id": {"type": "string"},
        "creator_id": {"type": "string"},
        "content": {"type": "object"},
        "signature": {"type": "string"},
        "timestamp": {"type": "number"}
    },
    "required": ["type", "action", "task_id", "creator_id", "content", "signature", "timestamp"],
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

# Define marketplace-specific message types
class TaskStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class Task:
    id: str
    creator_id: str
    title: str
    description: str
    requirements: Dict[str, Any]
    compensation: float
    status: TaskStatus
    created_at: float
    deadline: Optional[float]
    assigned_to: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

@dataclass
class Agent:
    id: str
    capabilities: List[str]
    reputation: float
    completed_tasks: int
    available: bool

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

    def get_public_key_pem(self) -> str:
        """Get public key in base64 format to avoid JSON encoding issues."""
        try:
            pem_bytes = self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            # Convert to base64 to avoid any JSON encoding issues
            return base64.b64encode(pem_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"Error encoding public key: {e}")
            raise

    def sign_message(self, msg_data: Dict[str, Any]) -> str:
        """Sign message data with consistent canonical format."""
        try:
            # Create canonical message string
            msg_string = json.dumps(msg_data, sort_keys=True, separators=(',', ':'))
            
            # Sign the message
            signature = self.private_key.sign(
                msg_string.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Signing error: {e}")
            raise

    def verify_signature(self, public_key_b64: str, data: bytes, signature_b64: bytes) -> bool:
        """Verify signature with base64 encoded public key."""
        try:
            # Decode the base64 public key
            public_key_pem = base64.b64decode(public_key_b64.encode('utf-8'))
            public_key = load_pem_public_key(public_key_pem)
            
            # Decode the base64 signature
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
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
        
    def _get_canonical_message(self, msg_data: Dict[str, Any]) -> str:
        """Create a canonical string representation of message data for signing/verification."""
        # Remove signature if present and sort keys
        filtered_data = {k: v for k, v in msg_data.items() if k != 'signature'}
        return json.dumps(filtered_data, sort_keys=True, separators=(',', ':'))

    def verify_message(self, msg_data: Dict[str, Any], signature_b64: str) -> bool:
        """Verify message signature."""
        try:
            # Create canonical message string
            msg_string = self._get_canonical_message(msg_data)
            logger.debug(f"Verifying message string: {msg_string}")
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify
            self.public_key.verify(
                signature,
                msg_string.encode('utf-8'),
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



class SecureServer:
    def __init__(
        self, 
        host: str = '0.0.0.0', 
        port: int = 55555, 
        cert_path: str = 'server.crt', 
        key_path: str = 'server.key', 
        password: str = 'server_default_password',
        max_connections: int = 100  # Increased max connections
    ):
        """Initialize the secure server with support for more connections."""
        self.host = host
        self.port = port
        self.peers: Dict[str, Peer] = {}
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60.0)
        self.max_connections = max_connections
        
        # Initialize security manager
        self.security_manager = SecurityManager(password)
        
        # Setup SSL context with proper certificate handling
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            # Allow self-signed certificates for testing
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        except Exception as e:
            logger.error(f"Failed to load certificates: {e}")
            raise

        
        # Create socket with SSL wrapper
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set TCP keepalive
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Increase socket buffer sizes
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        
        try:
            self.socket.bind((self.host, self.port))
            # Increase listen backlog
            self.socket.listen(self.max_connections)
            self.ssl_socket = self.ssl_context.wrap_socket(self.socket, server_side=True)
            logger.info(f"Server started on {host}:{port} with max {max_connections} connections")
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

        self.running = True
        self.active_connections = 0
        self.connection_lock = threading.Lock()

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
        """Start the server with connection tracking."""
        logger.info(f"[+] Server ready for connections (max {self.max_connections})...")
        
        while self.running:
            try:
                client, addr = self.ssl_socket.accept()
                if self.active_connections >= self.max_connections:
                    logger.warning("Maximum connections reached, rejecting new connection")
                    client.close()
                    continue
                    
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
        """Handle client with improved error handling."""
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            with self.connection_lock:
                self.active_connections += 1
                logger.info(f"Active connections: {self.active_connections}")

            if not self.rate_limiter.is_allowed(client_id):
                logger.warning(f"Rate limit exceeded for {client_id}")
                return

            # Receive data with size logging
            data = client.recv(4096)
            if data:
                logger.debug(f"Received {len(data)} bytes from {client_id}")
                logger.debug(f"Data preview: {data[:100]}...")  # Log first 100 bytes
                
                try:
                    msg = json.loads(data.decode('utf-8'))
                    
                    if msg['type'] == 'register':
                        # Validate message
                        jsonschema.validate(instance=msg, schema=REGISTER_MESSAGE_SCHEMA)
                        
                        # Log successful parsing
                        logger.debug(f"Successfully parsed registration message from {client_id}")
                        
                        # Handle registration
                        self._handle_registration(msg, client, addr)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error from {client_id}: {e}")
                    logger.debug(f"Problematic data: {data.decode('utf-8', errors='replace')}")
                    error_response = {
                        'type': 'error',
                        'message': 'Invalid JSON format'
                    }
                    client.send(json.dumps(error_response).encode())
                except Exception as e:
                    logger.error(f"Error processing message from {client_id}: {e}")
                    error_response = {
                        'type': 'error',
                        'message': str(e)
                    }
                    client.send(json.dumps(error_response).encode())
                    
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            with self.connection_lock:
                self.active_connections -= 1
            try:
                client.close()
            except:
                pass

    def _broadcast_peer_list(self, exclude_peer_id: Optional[str] = None):
        """Send updated peer list to all connected peers except the excluded one."""
        try:
            # Create peer list with only essential data
            peer_list = []
            for peer in self.peers.values():
                if exclude_peer_id and peer.id == exclude_peer_id:
                    continue
                    
                # Create a simplified peer dict with only necessary fields
                peer_data = {
                    'id': peer.id,
                    'host': peer.host,
                    'port': peer.port,
                    'last_seen': float(peer.last_seen),  # Ensure float for JSON serialization
                    'public_key': peer.public_key,
                    'nat_type': peer.nat_type
                }
                peer_list.append(peer_data)

            # Create response with explicit encoding handling
            response = {
                'type': 'peers',
                'peers': peer_list
            }
            
            # Use json.dumps with explicit encoding options
            try:
                response_json = json.dumps(response, 
                                        ensure_ascii=True,
                                        separators=(',', ':'),
                                        default=str)  # Handle any non-standard types
                response_data = response_json.encode('utf-8')
                
                # Log the size of the message
                logger.debug(f"Peer list message size: {len(response_data)} bytes")
                
                # Split large messages if needed (UDP fragmentation handling)
                MAX_UDP_SIZE = 65507  # Maximum safe UDP packet size
                if len(response_data) > MAX_UDP_SIZE:
                    logger.warning(f"Peer list too large ({len(response_data)} bytes), splitting not implemented")
                    # TODO: Implement message splitting for large peer lists
                    return
                
                # Create a UDP socket for broadcasting
                broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Send to each peer
                for peer in self.peers.values():
                    if exclude_peer_id and peer.id == exclude_peer_id:
                        continue
                        
                    try:
                        logger.info(f"Broadcasting peer list to {peer.id} at {peer.host}:{peer.port}")
                        broadcast_socket.sendto(response_data, (peer.host, peer.port))
                    except Exception as e:
                        logger.error(f"Failed to send peer list to {peer.id}: {e}")
                
                broadcast_socket.close()
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON encoding error: {e}")
                logger.debug(f"Problematic data: {str(response)[:200]}...")  # Log first 200 chars
            except Exception as e:
                logger.error(f"Error creating peer list message: {e}")
                
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
    
    def _handle_registration(self, msg: Dict, client: ssl.SSLSocket, addr: tuple):
        """Handle peer registration with fixed response serialization."""
        try:
            # Validate message schema
            jsonschema.validate(instance=msg, schema=REGISTER_MESSAGE_SCHEMA)
            
            # Create peer object
            peer = Peer(
                id=msg['peer_id'],
                host=addr[0],
                port=msg['port'],
                last_seen=time.time(),
                public_key=msg['public_key'],
                nat_type="unknown"
            )
            
            # Add peer with thread safety
            with self.connection_lock:
                self.peers[msg['peer_id']] = peer
            
            logger.info(f"New peer registered: {peer.id} ({peer.host}:{peer.port})")
            
            # Prepare peer list with minimal necessary data
            peer_list = []
            for p in self.peers.values():
                peer_data = {
                    'id': p.id,
                    'host': p.host,
                    'port': p.port,
                    'last_seen': round(float(p.last_seen), 3),  # Round to reduce decimal places
                    'public_key': p.public_key,
                    'nat_type': p.nat_type
                }
                peer_list.append(peer_data)

            # Create response with minimal data
            response = {
                'type': 'peers',
                'peers': peer_list
            }

            # Convert to JSON with explicit encoding options
            try:
                response_json = json.dumps(
                    response,
                    ensure_ascii=True,
                    separators=(',', ':'),
                    default=str
                )
                
                # Log response size for debugging
                response_bytes = response_json.encode('utf-8')
                logger.debug(f"Response size: {len(response_bytes)} bytes")
                
                # Send response in chunks if needed
                CHUNK_SIZE = 4096
                total_sent = 0
                while total_sent < len(response_bytes):
                    chunk = response_bytes[total_sent:total_sent + CHUNK_SIZE]
                    sent = client.send(chunk)
                    if sent == 0:
                        raise RuntimeError("Socket connection broken")
                    total_sent += sent

            except Exception as e:
                logger.error(f"Error sending response: {e}")
                error_response = {
                    'type': 'error',
                    'message': 'Internal server error'
                }
                client.send(json.dumps(error_response).encode())
                return
                
            # Broadcast updated peer list separately
            self._broadcast_peer_list(exclude_peer_id=msg['peer_id'])
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            error_response = {
                'type': 'error',
                'message': 'Registration failed'
            }
            client.send(json.dumps(error_response).encode())


class SecureNode:
    def __init__(self, rendezvous_server: str, rendezvous_port: int, network_password: str,
                 cert_path: str = 'server.crt'):
        self.peer_id = str(uuid.uuid4())
        self.peers: Dict[str, Peer] = {}
        self.rendezvous_server = rendezvous_server
        self.rendezvous_port = rendezvous_port
        
        # Security setup
        self.security_manager = SecurityManager(network_password)
        
        # Setup SSL context with proper certificate verification
        self.ssl_context = ssl.create_default_context()
        try:
            self.ssl_context.load_verify_locations(cert_path)
            # Allow self-signed certificates for testing
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
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

    def _validate_json_message(self, msg_data: Dict[str, Any]) -> bool:
        """Validate that all message components are JSON serializable
        
        Args:
            msg_data: Dictionary containing the message data
            
        Returns:
            bool: True if message is valid JSON, False otherwise
        """
        try:
            # Try to serialize the message
            json_str = json.dumps(msg_data)
            # Try to parse it back
            json.loads(json_str)
            return True
        except Exception as e:
            logging.error(f"JSON validation error: {str(e)}")
            # Log the problematic message data for debugging
            logging.debug(f"Problematic message data: {msg_data}")
            return False
        
    def connect(self, max_retries: int = 3, retry_delay: float = 2.0) -> bool:
        """Connect with improved response handling."""
        for attempt in range(max_retries):
            try:
                logger.info(f"Connection attempt {attempt + 1}/{max_retries}")
                
                with socket.create_connection(
                    (self.rendezvous_server, self.rendezvous_port),
                    timeout=10
                ) as sock:
                    with self.ssl_context.wrap_socket(
                        sock,
                        server_hostname=self.rendezvous_server
                    ) as ssl_sock:
                        # Prepare and send registration message
                        msg_data = self._prepare_registration_message()
                        message_json = json.dumps(msg_data)
                        ssl_sock.send(message_json.encode('utf-8'))
                        
                        # Receive response in chunks
                        chunks = []
                        while True:
                            try:
                                chunk = ssl_sock.recv(4096)
                                if not chunk:
                                    break
                                chunks.append(chunk)
                            except socket.timeout:
                                break
                                
                        if not chunks:
                            raise Exception("No response from server")
                            
                        # Combine chunks and decode
                        try:
                            data = b''.join(chunks)
                            response = json.loads(data.decode('utf-8'))
                            
                            if response['type'] == 'peers':
                                self._handle_peer_list(response)
                                logger.info("Successfully connected to network")
                                return True
                            elif response['type'] == 'error':
                                logger.error(f"Server error: {response['message']}")
                                raise Exception(f"Server error: {response['message']}")
                                
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse server response: {e}")
                            logger.debug(f"Raw response length: {len(data)} bytes")
                            logger.debug(f"Response preview: {data[:200]}...")
                            raise
                            
            except Exception as e:
                logger.error(f"Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
                    
        logger.error("All connection attempts failed")
        return False
    
    def _handle_peer_list(self, response: Dict):
        """Handle peer list update with improved error handling."""
        try:
            jsonschema.validate(instance=response, schema=PEERS_MESSAGE_SCHEMA)
            
            with threading.Lock():
                new_peers = {}
                for peer_data in response['peers']:
                    if peer_data['id'] != self.peer_id:
                        try:
                            # Clean and validate peer data
                            cleaned_data = {
                                'id': str(peer_data['id']),
                                'host': str(peer_data['host']),
                                'port': int(peer_data['port']),
                                'last_seen': float(peer_data['last_seen']),
                                'public_key': str(peer_data['public_key']),
                                'nat_type': str(peer_data.get('nat_type', 'unknown'))
                            }
                            peer = Peer(**cleaned_data)
                            new_peers[peer.id] = peer
                            
                        except (KeyError, ValueError, TypeError) as e:
                            logger.warning(f"Invalid peer data: {e}")
                            continue
                            
                self.peers = new_peers
                logger.info(f"Updated peer list, found {len(self.peers)} peers")
                
        except Exception as e:
            logger.error(f"Error handling peer list: {e}")

    def _listen_for_peers(self):
        """Listen for peer messages with improved error handling."""
        while self.running:
            try:
                data, addr = self.p2p_socket.recvfrom(65507)  # Maximum UDP packet size
                peer_addr = f"{addr[0]}:{addr[1]}"
                
                if not self.rate_limiter.is_allowed(peer_addr):
                    continue
                
                try:
                    msg_str = data.decode('utf-8')
                    msg = json.loads(msg_str)
                    
                    if msg['type'] == 'peers':
                        self._handle_peer_list(msg)
                    elif msg['type'] == 'message':
                        # Handle other message types...
                        pass
                        
                except UnicodeDecodeError as e:
                    logger.error(f"Failed to decode message from {peer_addr}: {e}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from {peer_addr}: {e}")
                    if len(msg_str) > 100:
                        logger.debug(f"Message preview: {msg_str[:100]}...")
                except Exception as e:
                    logger.error(f"Error processing message from {peer_addr}: {e}")
                    
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

    def _prepare_registration_message(self) -> Dict[str, Any]:
        """Prepare registration message with proper signature."""
        try:
            # Create the base message without signature
            msg_data = {
                'type': 'register',
                'peer_id': self.peer_id,
                'port': self.p2p_port,
                'server_port': self.server_port,
                'public_key': self.security_manager.get_public_key_pem()
            }
            
            # Create canonical message string for signing
            msg_string = json.dumps(msg_data, sort_keys=True, separators=(',', ':'))
            
            # Sign the canonical message
            signature = self.security_manager.sign_message(msg_data)
            msg_data['signature'] = signature
            
            return msg_data
            
        except Exception as e:
            logger.error(f"Error preparing registration message: {e}")
            raise



class MarketplaceNode(SecureNode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tasks: Dict[str, Task] = {}
        self.agent_info = Agent(
            id=self.peer_id,
            capabilities=self._get_agent_capabilities(),
            reputation=1.0,
            completed_tasks=0,
            available=True
        )
        self.bids: Dict[str, Dict[str, float]] = {}  # task_id -> {agent_id: bid_amount}
        
    def _get_agent_capabilities(self) -> List[str]:
        """Define agent's capabilities - override this in specific agent implementations"""
        return ["text_analysis", "data_processing"]  # Example capabilities

    def create_task(self, title: str, description: str, requirements: Dict[str, Any], 
                   compensation: float, deadline: Optional[float] = None) -> str:
        """Create a new task in the marketplace"""
        task_id = str(uuid.uuid4())
        task = Task(
            id=task_id,
            creator_id=self.peer_id,
            title=title,
            description=description,
            requirements=requirements,
            compensation=compensation,
            status=TaskStatus.OPEN,
            created_at=time.time(),
            deadline=deadline
        )
        self.tasks[task_id] = task
        
        # Broadcast task to network
        self._broadcast_task("create", task_id, asdict(task))
        return task_id

    def bid_on_task(self, task_id: str, bid_amount: float):
        """Submit a bid for a task"""
        if task_id not in self.tasks or self.tasks[task_id].status != TaskStatus.OPEN:
            return False
            
        if not self._verify_capability_requirements(self.tasks[task_id].requirements):
            return False
            
        bid_content = {
            "bid_amount": bid_amount,
            "agent_capabilities": self.agent_info.capabilities,
            "agent_reputation": self.agent_info.reputation
        }
        
        self._broadcast_task("bid", task_id, bid_content)
        return True

    def _verify_capability_requirements(self, requirements: Dict[str, Any]) -> bool:
        """Check if agent meets task requirements"""
        required_capabilities = requirements.get("capabilities", [])
        return all(cap in self.agent_info.capabilities for cap in required_capabilities)

    def submit_task_result(self, task_id: str, result: Dict[str, Any]):
        """Submit results for a completed task"""
        if (task_id not in self.tasks or 
            self.tasks[task_id].status != TaskStatus.IN_PROGRESS or
            self.tasks[task_id].assigned_to != self.peer_id):
            return False
            
        self._broadcast_task("submit", task_id, result)
        return True

    def validate_task_result(self, task_id: str, is_valid: bool, feedback: str = ""):
        """Validate submitted task results (for task creators)"""
        if task_id not in self.tasks or self.tasks[task_id].creator_id != self.peer_id:
            return False
            
        validation_content = {
            "is_valid": is_valid,
            "feedback": feedback
        }
        
        if is_valid:
            self._update_agent_reputation(self.tasks[task_id].assigned_to, 1.0)
        else:
            self._update_agent_reputation(self.tasks[task_id].assigned_to, -0.5)
            
        self._broadcast_task("validate", task_id, validation_content)
        return True

    def _update_agent_reputation(self, agent_id: str, change: float):
        """Update agent reputation based on task performance"""
        if agent_id == self.peer_id:
            new_reputation = max(0.1, min(5.0, self.agent_info.reputation + change))
            self.agent_info.reputation = new_reputation
            if change > 0:
                self.agent_info.completed_tasks += 1

    def _broadcast_task(self, action: str, task_id: str, content: Dict[str, Any]):
        """Broadcast task-related messages to the network"""
        msg_data = {
            'type': 'task',
            'action': action,
            'task_id': task_id,
            'creator_id': self.peer_id,
            'content': content,
            'timestamp': time.time()
        }
        
        # Sign message
        signature = self.security_manager.sign(
            json.dumps({k: v for k, v in msg_data.items() if k != 'signature'}).encode()
        )
        msg_data['signature'] = signature.decode()
        
        # Send to all peers
        msg_bytes = json.dumps(msg_data).encode()
        for peer in self.peers.values():
            try:
                self.p2p_socket.sendto(msg_bytes, (peer.host, peer.port))
            except Exception as e:
                logger.error(f"Failed to send task message to {peer.id}: {e}")

    def _handle_task_message(self, msg: Dict[str, Any], peer: Peer):
        """Handle incoming task-related messages"""
        try:
            # Verify signature
            if not self.security_manager.verify_signature(
                peer.public_key,
                json.dumps({k: v for k, v in msg.items() if k != 'signature'}).encode(),
                msg['signature'].encode()
            ):
                logger.warning(f"Invalid task message signature from {msg['creator_id']}")
                return

            action = msg['action']
            task_id = msg['task_id']
            content = msg['content']

            if action == "create":
                if task_id not in self.tasks:
                    self.tasks[task_id] = Task(**content)
                    logger.info(f"New task received: {task_id}")
                    
            elif action == "bid":
                if task_id in self.tasks and self.tasks[task_id].status == TaskStatus.OPEN:
                    if task_id not in self.bids:
                        self.bids[task_id] = {}
                    self.bids[task_id][msg['creator_id']] = content['bid_amount']
                    
            elif action == "submit":
                if (task_id in self.tasks and 
                    self.tasks[task_id].status == TaskStatus.IN_PROGRESS and
                    msg['creator_id'] == self.tasks[task_id].assigned_to):
                    self.tasks[task_id].result = content
                    self.tasks[task_id].status = TaskStatus.COMPLETED
                    
            elif action == "validate":
                if task_id in self.tasks and self.tasks[task_id].status == TaskStatus.COMPLETED:
                    if content['is_valid']:
                        logger.info(f"Task {task_id} validated successfully")
                    else:
                        logger.warning(f"Task {task_id} validation failed: {content['feedback']}")
                        self.tasks[task_id].status = TaskStatus.FAILED

        except Exception as e:
            logger.error(f"Error processing task message: {e}")

    def _listen_for_peers(self):
        """Override parent method to handle marketplace messages"""
        while self.running:
            try:
                data, addr = self.p2p_socket.recvfrom(4096)
                try:
                    msg = json.loads(data.decode())
                    if msg['type'] == 'task':
                        peer = self.peers.get(msg['creator_id'])
                        if peer:
                            self._handle_task_message(msg, peer)
                    else:
                        # Handle regular P2P messages
                        super()._listen_for_peers()
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
            except Exception as e:
                if self.running:
                    logger.error(f"Listener error: {e}")


def generate_certificates(host: str):
    """Generate self-signed certificates for testing"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Test Unit"),
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
            x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Save certificate and private key
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    
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
