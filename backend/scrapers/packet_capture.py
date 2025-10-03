"""
Network packet capture module using Scapy with Linux privilege escalation
"""
import asyncio
import json
import logging
import subprocess
import sys
import os
from typing import Dict, Any, Callable, Optional
from scapy.all import sniff, Packet as ScapyPacket, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
from queue import Queue
import signal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    """Handles network packet capture with Scapy"""
    
    def __init__(self):
        self.capture_active = False
        self.packet_queue = Queue()
        self.capture_thread = None
        
        # Check if running with sufficient privileges
        self._check_privileges()
        
        # Disable Scapy verbosity
        conf.verb = 0
    
    def _check_privileges(self):
        """Check if we have necessary privileges for packet capture"""
        if os.geteuid() != 0:
            logger.warning("Not running as root. Packet capture may require sudo privileges.")
            return False
        return True
    
    def _escalate_privileges(self):
        """Attempt to escalate privileges on Linux"""
        if sys.platform == "linux" or sys.platform == "linux2":
            # Check if we can use sudo
            try:
                result = subprocess.run(
                    ["sudo", "-n", "true"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    logger.info("Can use sudo without password")
                    return True
            except Exception as e:
                logger.error(f"Cannot escalate privileges: {e}")
                return False
        return False
    
    def parse_packet(self, packet: ScapyPacket) -> Dict[str, Any]:
        """Convert Scapy packet to dictionary format"""
        packet_data = {
            "timestamp": float(packet.time),
            "layers": [],
            "raw_payload": None,
            "size": len(packet)
        }
        
        # Parse each layer
        layer = packet
        while layer:
            layer_info = {
                "name": layer.__class__.__name__,
                "fields": {}
            }
            
            # Extract relevant fields based on layer type
            if layer.haslayer(IP):
                ip_layer = layer[IP]
                layer_info["fields"] = {
                    "src": ip_layer.src,
                    "dst": ip_layer.dst,
                    "version": ip_layer.version,
                    "ttl": ip_layer.ttl,
                    "proto": ip_layer.proto
                }
            
            elif layer.haslayer(TCP):
                tcp_layer = layer[TCP]
                layer_info["fields"] = {
                    "sport": tcp_layer.sport,
                    "dport": tcp_layer.dport,
                    "flags": str(tcp_layer.flags),
                    "seq": tcp_layer.seq,
                    "ack": tcp_layer.ack
                }
            
            elif layer.haslayer(UDP):
                udp_layer = layer[UDP]
                layer_info["fields"] = {
                    "sport": udp_layer.sport,
                    "dport": udp_layer.dport,
                    "len": udp_layer.len
                }
            
            elif layer.haslayer(ICMP):
                icmp_layer = layer[ICMP]
                layer_info["fields"] = {
                    "type": icmp_layer.type,
                    "code": icmp_layer.code
                }
            
            elif layer.haslayer(HTTPRequest):
                http_layer = layer[HTTPRequest]
                layer_info["fields"] = {
                    "method": http_layer.Method.decode() if http_layer.Method else None,
                    "host": http_layer.Host.decode() if http_layer.Host else None,
                    "path": http_layer.Path.decode() if http_layer.Path else None,
                    "http_version": http_layer.Http_Version.decode() if http_layer.Http_Version else None
                }
            
            elif layer.haslayer(HTTPResponse):
                http_layer = layer[HTTPResponse]
                layer_info["fields"] = {
                    "status_code": http_layer.Status_Code.decode() if http_layer.Status_Code else None,
                    "reason_phrase": http_layer.Reason_Phrase.decode() if http_layer.Reason_Phrase else None
                }
            
            # Add generic fields for any layer
            for field in layer.fields_desc:
                field_name = field.name
                if field_name not in layer_info["fields"]:
                    try:
                        field_value = getattr(layer, field_name)
                        if field_value is not None and isinstance(field_value, (str, int, float, bool)):
                            layer_info["fields"][field_name] = field_value
                    except:
                        pass
            
            packet_data["layers"].append(layer_info)
            
            # Move to next layer
            layer = layer.payload if layer.payload and layer.payload != b'' else None
            if isinstance(layer, bytes):
                packet_data["raw_payload"] = layer.hex() if layer else None
                break
        
        return packet_data
    
    def _capture_worker(self, filter_string: str, interface: str, callback: Callable):
        """Worker thread for packet capture"""
        def packet_handler(packet: ScapyPacket):
            """Handle each captured packet"""
            try:
                parsed = self.parse_packet(packet)
                self.packet_queue.put(parsed)
                
                # Call the callback if provided
                if callback:
                    callback(parsed)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        
        try:
            logger.info(f"Starting capture on interface {interface} with filter: {filter_string}")
            
            # Start sniffing
            sniff(
                filter=filter_string if filter_string else None,
                iface=interface if interface != "any" else None,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.capture_active
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.capture_active = False
    
    async def start_capture(
        self, 
        filter_string: str = "", 
        interface: str = "any",
        session_id: str = None,
        callback: Optional[Callable] = None
    ):
        """Start packet capture asynchronously"""
        if self.capture_active:
            raise RuntimeError("Capture already active")
        
        self.capture_active = True
        
        # Start capture in separate thread to avoid blocking
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(filter_string, interface, callback),
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info(f"Packet capture started for session {session_id}")
        
        # Keep the async task alive
        while self.capture_active:
            await asyncio.sleep(1)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Packet capture stopped")
    
    def get_available_interfaces(self) -> list:
        """Get list of available network interfaces"""
        try:
            from scapy.arch import get_if_list
            return get_if_list()
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return []
    
    def validate_filter(self, filter_string: str) -> bool:
        """Validate a BPF filter string"""
        try:
            from scapy.arch import compile_filter
            compile_filter(filter_string)
            return True
        except Exception as e:
            logger.error(f"Invalid filter: {e}")
            return False


class PrivilegedPacketCapture(PacketCapture):
    """Extended packet capture with automatic privilege escalation for Linux"""
    
    def __init__(self):
        super().__init__()
        self.elevated_process = None
    
    def start_with_privileges(
        self,
        filter_string: str = "",
        interface: str = "any",
        session_id: str = None
    ):
        """Start packet capture with elevated privileges"""
        if os.geteuid() != 0:
            # Need to run as root
            logger.info("Attempting to run with elevated privileges...")
            
            # Create a standalone capture script
            capture_script = f"""
import sys
import json
from scapy.all import sniff, conf
conf.verb = 0

def packet_handler(packet):
    packet_dict = {{
        "timestamp": float(packet.time),
        "summary": packet.summary(),
        "layers": []
    }}
    
    layer = packet
    while layer:
        layer_name = layer.__class__.__name__
        packet_dict["layers"].append(layer_name)
        layer = layer.payload if hasattr(layer, 'payload') else None
        if isinstance(layer, bytes):
            break
    
    print(json.dumps(packet_dict))
    sys.stdout.flush()

try:
    sniff(
        filter="{filter_string}" if "{filter_string}" else None,
        iface="{interface}" if "{interface}" != "any" else None,
        prn=packet_handler,
        store=False,
        count=0
    )
except KeyboardInterrupt:
    sys.exit(0)
except Exception as e:
    print(f"ERROR: {{e}}", file=sys.stderr)
    sys.exit(1)
"""
            
            # Run with sudo
            self.elevated_process = subprocess.Popen(
                ["sudo", sys.executable, "-c", capture_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            logger.info(f"Elevated packet capture started for session {session_id}")
            return self.elevated_process
        else:
            # Already running as root
            return asyncio.create_task(
                self.start_capture(filter_string, interface, session_id)
            )
    
    def stop_privileged_capture(self):
        """Stop the elevated capture process"""
        if self.elevated_process:
            self.elevated_process.terminate()
            try:
                self.elevated_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.elevated_process.kill()
            self.elevated_process = None
        else:
            self.stop_capture()


if __name__ == "__main__":
    # Test packet capture
    import asyncio
    
    async def test_capture():
        capture = PacketCapture()
        
        # Check available interfaces
        interfaces = capture.get_available_interfaces()
        print(f"Available interfaces: {interfaces}")
        
        # Test filter validation
        test_filter = "tcp port 80 or tcp port 443"
        is_valid = capture.validate_filter(test_filter)
        print(f"Filter '{test_filter}' valid: {is_valid}")
        
        # Capture packets for 10 seconds
        def packet_callback(packet):
            print(f"Captured packet: {packet['layers']}")
        
        capture_task = asyncio.create_task(
            capture.start_capture(
                filter_string=test_filter,
                callback=packet_callback
            )
        )
        
        # Run for 10 seconds
        await asyncio.sleep(10)
        
        # Stop capture
        capture.stop_capture()
        await capture_task
    
    # Run test
    asyncio.run(test_capture())