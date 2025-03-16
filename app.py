import datetime
from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles  # Import for serving static files
from fastapi.responses import FileResponse
import os
import uvicorn
import json
import multiprocessing
import socket
import sys
import re
import signal
from modules.subdomain import send_request
from modules.activation import recon_1, recon_2
if sys.platform != "win32":
    multiprocessing.set_start_method("fork", force=True)
import psutil
from modules._recon_ import check_redirect

app = FastAPI()

# Detect if running inside PyInstaller
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS  # PyInstaller temp directory
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Correctly locate `static/` directory
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")

# Ensure static directory exists before mounting
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
else:
    print(f"⚠️ WARNING: Static directory '{STATIC_DIR}' not found!")

# Enable CORS for frontend
    
scan_file = "./data/scan.json"
# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


active_connections = []

processes = []
@app.get("/")
async def root():
    return FileResponse("static/index.html")  # Serve index.html properly

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Handles WebSocket connections"""
    await websocket.accept()
    active_connections.append(websocket)
    print("Client connected!")
    try:
        while True:
            data = await websocket.receive_text()
            print(f"Received: {data}")

    except Exception as e:
        print(f"Client disconnected: {e}")
    finally:
        active_connections.remove(websocket)
        await websocket.close()
        
        


scan_file = "./data/scan.json"
processes = []  # Track active processes

@app.post("/submit_target")
async def submit_target(request: Request):
    """Submit target details, store them in scan.json, and start scanning processes."""
    data = await request.json()
    name = data.get("name")
    target = data.get("target")
    spider = data.get("spider")
    query_search = data.get("query_search")

    if not name or not target:
        raise HTTPException(status_code=400, detail="Name and target are required.")

    # Check if target is a URL or raw IP/domain
    url_pattern = re.compile(r'^(http://|https://)([a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(:[0-9]{1,5})?(/.*)?$')
    match = url_pattern.match(target)

    if match:
        domain = match.group(2)
        port = match.group(3) if match.group(3) else ''
        FINAL_TARGET = f"{domain}{port}"  # Full domain + port if exists
        TYPE = "url"
    else:
        FINAL_TARGET = target
        TYPE = "ip"

    # Ensure scan.json directory exists
    os.makedirs(os.path.dirname(scan_file), exist_ok=True)

    # Load or initialize scan.json
    try:
        with open(scan_file, "r") as file:
            scan_data = json.load(file)
            if not isinstance(scan_data, list):
                scan_data = []
    except (FileNotFoundError, json.JSONDecodeError):
        scan_data = []

    # Check DNS resolution
    dns_host, exists = check_redirect(FINAL_TARGET)
    value = dns_host if exists else ""
    if value == FINAL_TARGET:
        value = ""

    # Append new entry without overwriting existing data
    new_entry = {
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": FINAL_TARGET,
        "dns_host": value,
    }
    scan_data.append(new_entry)

    # Save updated scan data
    with open(scan_file, "w") as file:
        json.dump(scan_data, file, indent=4)

    # Function wrapper for scanning processes
    def run_scan():
        recon_1(spider, query_search, target=target, domain=FINAL_TARGET)

    def run_scan_ip():
        recon_2(spider, query_search, FINAL_TARGET)

    # Start scanning process based on type
    process = multiprocessing.Process(target=run_scan if TYPE == "url" else run_scan_ip, daemon=False)
    processes.append(process)
    process.start()

    # Send WebSocket update (if applicable)
    message = {"type": "banner", "value": f"Target set to {FINAL_TARGET}"}
    if active_connections:
        for connection in active_connections:
            await connection.send_text(json.dumps(message))

    return message

@app.post("/send_message")
async def send_message(request: Request):
    """API to send a message to all WebSocket clients"""
    try:
        # Parse the JSON body
        message = await request.json()
        
        
        if active_connections:
            for connection in active_connections:
                await connection.send_text(json.dumps(message))  # Send the message as JSON
            return {"status": "Message sent to all clients"}
        else:
            return {"status": "No active WebSocket connections"}
    except Exception as e:
        return {"status": "Error", "error": str(e)}

@app.post("/stop_scan")
async def stop_scan():
    """Forcefully stop all threads, processes, and exit FastAPI."""
    
    print("🛑 Stopping all running scans...")
    
    # Kill all child processes
    parent = psutil.Process(os.getpid())
    for child in parent.children(recursive=True):
        print(f"🔴 Killing process: {child.pid}")
        child.terminate()  # Send SIGTERM
        try:
            child.wait(timeout=3)  # Wait for termination
        except psutil.TimeoutExpired:
            print(f"⚠️ Process {child.pid} did not exit, force killing.")
            child.kill()  # Force kill if not terminated
    
    # Kill main process (FastAPI)
    print("🚨 Exiting application...")
    os._exit(0)  # Immediate exit

    return {"message": "Scan stopped and application exited."}

def cleanup():
    """Cleanup function to terminate all running processes."""
    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join()  # Wait for the process to terminate
    print("All processes terminated.")

def signal_handler(sig, frame):
    """Handle termination signals."""
    print("Received termination signal. Cleaning up...")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def is_server_running(host="127.0.0.1", port=12531):
    """Check if the server is already running to avoid multiple browser tabs."""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def run_server():
    """Runs the FastAPI server with suppressed output."""
    print("🚀 Welcome to ONI-DIR! Please visit http://127.0.0.1:12531")  # ✅ Custom message

    # ✅ Suppress all unwanted terminal output
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")

    # Start server
    uvicorn.run("app:app", host="127.0.0.1", port=12531, log_level="critical")
    
if __name__ == "__main__":

    run_server()
    
signal.signal(signal.SIGTERM, signal_handler)