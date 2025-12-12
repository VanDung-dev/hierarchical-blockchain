"""
ZeroMQ Transport Layer for HieraChain.

This module implements a high-performance network transport using ZeroMQ (pyzmq).
It provides a `ZmqNode` class that handles:
- Asynchronous message sending (DEALER sockets).
- Message receiving (ROUTER sockets) with identity management.
- Serialization of messages (JSON by default, extensible).
"""

import zmq
import zmq.asyncio
import json
import asyncio
import logging
from typing import Dict, Any, Callable, Optional, List

logger = logging.getLogger(__name__)

class NetworkError(Exception):
    """Base exception for network errors."""
    pass

class ZmqNode:
    """
    A ZeroMQ-based network node.
    
    Attributes:
        node_id (str): Unique identifier for this node.
        port (int): The port to bind for listening (ROUTER).
        peers (Dict[str, str]): Mapping of peer_id -> address (e.g., "tcp://127.0.0.1:5001").
    """
    
    def __init__(self, node_id: str, port: int, host: str = "127.0.0.1"):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.address = f"tcp://{host}:{port}"
        self.peers: Dict[str, str] = {}  # peer_id -> address
        
        self.ctx = zmq.asyncio.Context()
        self._stop_event = asyncio.Event()
        self._message_handler: Optional[Callable[[Dict[str, Any], str], Any]] = None
        
        # Sockets
        self.router = None  # For receiving (bind)
        self.dealer_pool: Dict[str, zmq.asyncio.Socket] = {} # For sending (connect)

    async def start(self):
        """Start the node: bind listener and start receiver loop."""
        try:
            self.router = self.ctx.socket(zmq.ROUTER)
            self.router.setsockopt(zmq.IDENTITY, self.node_id.encode('utf-8'))
            self.router.bind(self.address)
            logger.info(f"Node {self.node_id} listening on {self.address}")
            
            # Start receiver loop in background
            asyncio.create_task(self._receiver_loop())
        except Exception as e:
            raise NetworkError(f"Failed to start node {self.node_id}: {e}")

    async def stop(self):
        """Stop the node and close sockets."""
        self._stop_event.set()
        
        if self.router:
            self.router.close()
        
        for peer_id, socket in self.dealer_pool.items():
            socket.close()
            
        self.ctx.term()
        logger.info(f"Node {self.node_id} stopped")

    def register_peer(self, peer_id: str, address: str):
        """Register a known peer."""
        self.peers[peer_id] = address

    def set_handler(self, handler: Callable[[Dict[str, Any], str], Any]):
        """Set the callback function for processing received messages."""
        self._message_handler = handler

    async def send_direct(self, target_peer_id: str, message: Dict[str, Any]) -> bool:
        """
        Send a message directly to a peer.
        
        Args:
            target_peer_id: Destination node ID.
            message: Dictionary message content.
        """
        if target_peer_id not in self.peers:
            logger.error(f"Unknown peer: {target_peer_id}")
            return False

        try:
            socket = await self._get_or_create_dealer(target_peer_id)
            encoded_msg = json.dumps(message).encode('utf-8')
            # Multipart: [empty (delimiter), message] for Dealer-Router pattern compatibility if needed,
            # but standard Dealer-Router usually handles framing.
            # Here we just send the message payload. Identity is handled by connect.
            await socket.send(encoded_msg)
            return True
        except Exception as e:
            logger.error(f"Failed to send to {target_peer_id}: {e}")
            return False

    async def broadcast(self, message: Dict[str, Any], exclude: List[str] = None):
        """Broadcast message to all registered peers."""
        exclude = exclude or []
        for peer_id in self.peers:
            if peer_id not in exclude:
                await self.send_direct(peer_id, message)

    async def _get_or_create_dealer(self, peer_id: str) -> zmq.asyncio.Socket:
        """Get existing DEALER socket or create a new one."""
        if peer_id in self.dealer_pool:
            return self.dealer_pool[peer_id]
            
        address = self.peers[peer_id]
        socket = self.ctx.socket(zmq.DEALER)
        # Set our identity so receiver knows who we are
        socket.setsockopt(zmq.IDENTITY, self.node_id.encode('utf-8'))
        socket.connect(address)
        
        self.dealer_pool[peer_id] = socket
        return socket

    async def _receiver_loop(self):
        """Loop to receive messages from ROUTER socket."""
        while not self._stop_event.is_set():
            try:
                # ROUTER receives multipart: [sender_id, empty, message] or [sender_id, message]
                # depending on peer type. With DEALER peer, it's usually [sender_id, message]
                msg_parts = await self.router.recv_multipart()
                
                if len(msg_parts) < 2:
                    continue
                    
                sender_id_bytes = msg_parts[0]
                message_bytes = msg_parts[-1] # Payload is the last part
                
                sender_id = sender_id_bytes.decode('utf-8')
                message_str = message_bytes.decode('utf-8')
                
                try:
                    message_data = json.loads(message_str)
                    if self._message_handler:
                        # Process message (could be async or sync)
                        if asyncio.iscoroutinefunction(self._message_handler):
                            await self._message_handler(message_data, sender_id)
                        else:
                            self._message_handler(message_data, sender_id)
                except json.JSONDecodeError:
                    logger.warning(f"Received invalid JSON from {sender_id}")
                    
            except zmq.ZMQError as e:
                if not self._stop_event.is_set():
                    logger.error(f"ZMQ Receive error: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error in receiver loop: {e}")
                await asyncio.sleep(1)
