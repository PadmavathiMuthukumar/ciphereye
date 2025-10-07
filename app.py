from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
from live_ids import capture_packets, get_active_interface
import queue
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask and SocketIO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Required for SocketIO
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading',
                   logger=True,
                   engineio_logger=True)

# Global variables
capture_thread = None
thread_lock = threading.Lock()
packet_queue = queue.Queue(maxsize=100)  # Buffer for packet data
is_capturing = False
selected_interface = None

@app.route('/')
def index():
    """Render the main dashboard page"""
    try:
        interface = get_active_interface()
        return render_template('index.html', interface=interface)
    except Exception as e:
        logger.error(f"Error getting network interface: {e}")
        return render_template('index.html', interface=None, error=str(e))

def background_capture():
    """Background thread that captures packets"""
    global is_capturing
    
    logger.info("Starting packet capture thread")
    socketio.emit('capture_status', {'status': 'started', 'interface': selected_interface})
    
    # Initialize counters for total statistics
    total_benign = 0
    total_malicious = 0
    
    while is_capturing:
        try:
            if selected_interface:
                # Capture a small batch of packets
                packets = capture_packets(selected_interface, packet_count=5)
                if packets:
                    logger.info(f"Captured {len(packets)} packets")
                
                if packets:
                    # Calculate batch statistics
                    benign_count = sum(1 for p in packets if p.get("label") == "Benign")
                    malicious_count = sum(1 for p in packets if p.get("label") == "Malicious")
                    
                    # Update total statistics
                    total_benign += benign_count
                    total_malicious += malicious_count
                    
                    # Format packet data for display
                    formatted_packets = []
                    for p in packets:
                        formatted_packet = {
                            "size": p.get("pkt_size_mean", 0),
                            "syn": p.get("syn_flag_count", 0),
                            "ack": p.get("ack_flag_count", 0),
                            "fin": p.get("fin_flag_count", 0),
                            "psh": p.get("psh_flag_count", 0),
                            "label": p.get("label", "Unknown")
                        }
                        formatted_packets.append(formatted_packet)
                    
                    # Create data packet for frontend
                    data = {
                        'packets': formatted_packets,
                        'stats': {
                            'benign': total_benign,
                            'malicious': total_malicious,
                            'total': total_benign + total_malicious
                        },
                        'batch_stats': {
                            'benign': benign_count,
                            'malicious': malicious_count,
                            'total': len(packets)
                        }
                    }
                    
                    # Log the data being sent
                    logger.info(f"Sending data: {data}")
                    
                    # Emit to all clients
                    socketio.emit('packet_data', data)
            
            # Small delay to prevent CPU overuse
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Error in capture thread: {e}")
            socketio.emit('capture_error', {'error': str(e)})
            time.sleep(1)  # Wait a bit longer on error
    
    logger.info("Packet capture thread stopped")

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    emit('connect_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")

@socketio.on('start_capture')
def handle_start_capture():
    """Start packet capture"""
    global is_capturing, capture_thread, selected_interface
    
    try:
        with thread_lock:
            if not is_capturing:
                selected_interface = get_active_interface()
                is_capturing = True
                capture_thread = socketio.start_background_task(background_capture)
                emit('capture_status', {
                    'status': 'started',
                    'interface': selected_interface
                })
                logger.info(f"Started capture on interface: {selected_interface}")
            else:
                emit('capture_status', {
                    'status': 'already_running',
                    'interface': selected_interface
                })
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        emit('capture_error', {'error': str(e)})

@socketio.on('stop_capture')
def handle_stop_capture():
    """Stop packet capture"""
    global is_capturing
    
    try:
        with thread_lock:
            is_capturing = False
            if capture_thread:
                # Let the capture thread finish naturally
                time.sleep(1)
            emit('capture_status', {'status': 'stopped'})
            logger.info("Stopped packet capture")
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        emit('capture_error', {'error': str(e)})

if __name__ == "__main__":
    try:
        logger.info("Starting CipherEye IDS Server...")
        # Start the server with specific host and port
        socketio.run(app, 
                    host='127.0.0.1',
                    port=5000,
                    debug=True,
                    use_reloader=True,
                    allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        if capture_thread and capture_thread.is_alive():
            is_capturing = False
            capture_thread.join(timeout=5)
