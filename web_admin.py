from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import asyncio
import secrets
from datetime import datetime
from typing import Set
from pathlib import Path
import uvicorn
from ddos_detector import DDoSDetector
from load_balancer import LoadBalancer
from web_server import WebServer
from custom_logging import log_event
from config import SystemConfig

templates_dir = Path("templates")
templates_dir.mkdir(exist_ok=True)

app = FastAPI(title="DDoS Protection System")
security = HTTPBasic()
templates = Jinja2Templates(directory="templates")
config = SystemConfig.get_config()

async def init():
    servers = [
        WebServer(
            host=config['host'],
            port=port,
            max_connections=config['rate_limits']['connections_per_ip']
        ) for port in config['server_ports']
    ]
    
    load_balancer = LoadBalancer(servers)
    detector = DDoSDetector(window_size=config['detection_window'])
    
    return servers, load_balancer, detector

servers = []
load_balancer = None
detector = None

active_connections: Set[WebSocket] = set()

async def login(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, config['security']['admin_username'])
    correct_password = secrets.compare_digest(credentials.password, config['security']['admin_password'])
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.on_event("startup")
async def startup_event():
    global servers, load_balancer, detector
    
    try:
        servers, load_balancer, detector = await init()
        
        for server in servers:
            server.start()
        
        await load_balancer.start()
        await detector.start()
        
        log_event("INFO", "System", "All components started successfully")
    except Exception as e:
        log_event("ERROR", "System", f"Startup failed: {str(e)}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    try:
        if load_balancer:
            await load_balancer.stop()
        if detector:
            await detector.stop()
        for server in servers:
            server.stop()
        
        log_event("INFO", "System", "All components stopped successfully")
    except Exception as e:
        log_event("ERROR", "System", f"Shutdown error: {str(e)}")

@app.get("/admin")
async def admin_dashboard(
    request: Request,
    username: str = Depends(login)
):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "username": username}
    )

@app.get("/admin/metrics")
async def get_metrics():
    try:
        detection_metrics = await detector.get_metrics()
        lb_metrics = await load_balancer.get_metrics()
        
        return {
            "detection": detection_metrics,
            "load_balancing": lb_metrics,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        log_event("ERROR", "Metrics", f"Error getting metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching metrics")

@app.websocket("/admin/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    
    try:
        while True:
            try:
                detection_metrics = await detector.get_metrics()
                lb_metrics = await load_balancer.get_metrics()
                
                metrics = {
                    "timestamp": datetime.now().isoformat(),
                    "traffic": lb_metrics["traffic"],
                    "servers": lb_metrics["servers"],
                    "mitigation": {
                        "active_rules": lb_metrics["mitigation"]["active_rules"],
                        "total_rules": lb_metrics["mitigation"]["total_rules"],
                        "throttled_ips": lb_metrics["mitigation"]["throttled_ips"]
                    },
                    "detection": {
                        "suspicious_ips": detection_metrics["suspicious_ips"],
                        "top_offenders": detection_metrics["top_offenders"],
                        "total_requests": detection_metrics["total_requests"],
                        "blocked_requests": detection_metrics["blocked_requests"]
                    }
                }
                
                await websocket.send_json(metrics)
                await asyncio.sleep(1)
                
            except Exception as e:
                log_event("ERROR", "WebSocket", f"Error sending metrics: {str(e)}")
                break
                
    except WebSocketDisconnect:
        log_event("INFO", "WebSocket", "Client disconnected")
    finally:
        active_connections.discard(websocket)
        try:
            await websocket.close()
        except:
            pass

@app.get("/")
async def root(request: Request):
    try:
        client_ip = request.client.host
        log_event("INFO", "Request Handler", f"Incoming request from {client_ip}")

        analysis = await detector.record_request(
            ip=client_ip,
            path=str(request.url.path),
            method=request.method,
            size=len(await request.body()),
            status_code=200
        )

        if analysis.get('recommendations'):
            await load_balancer.handle_recommendations(analysis['recommendations'])

        # Check if request should be blocked
        server, block_reason = await load_balancer.select_server(client_ip)
        
        if block_reason:
            return HTMLResponse(
                content=blocked_page(block_reason),
                status_code=403
            )
            
        if not server:
            return HTMLResponse(
                content=error_page("No servers available"),
                status_code=503
            )

        try:
            response_content = await server.handle_request()
            return HTMLResponse(
                content=response_content,
                status_code=200
            )
        finally:
            if server:
                await load_balancer.release_server(server)
            
    except Exception as e:
        log_event("ERROR", "Request Handler", f"Error: {str(e)}")
        return HTMLResponse(
            content=error_page("Internal server error"),
            status_code=500
        )

def blocked_page(reason: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Blocked</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100 min-h-screen flex flex-col items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
            <div class="flex items-center justify-center w-16 h-16 rounded-full bg-red-100 mx-auto mb-4">
                <svg class="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-center text-red-600 mb-4">Access Blocked</h1>
            <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
                <p class="text-red-700">{reason}</p>
            </div>
            <p class="text-gray-600 text-center">
                If you believe this is a mistake, please contact the system administrator.
            </p>
        </div>
    </body>
    </html>
    """

def error_page(message: str) -> str:
    return blocked_page(f"Error: {message}")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config['admin_port'],
        log_level="info"
    )