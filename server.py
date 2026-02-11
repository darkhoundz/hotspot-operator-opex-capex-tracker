import http.server
import socketserver
import json
import os
from http import HTTPStatus

PORT = 8000
DATA_DIR = 'data'

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        # Map endpoints to files
        endpoints = {
            '/save-data': 'financials.json',
            '/save-settings': 'settings.json'
        }

        if self.path in endpoints:
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                
                # Parse JSON to ensure it's valid before writing
                data = json.loads(post_data)
                
                filename = endpoints[self.path]
                filepath = os.path.join(DATA_DIR, filename)
                
                # Ensure directory exists
                os.makedirs(DATA_DIR, exist_ok=True)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                response = {'status': 'success', 'message': f'Saved to {filename}'}
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except json.JSONDecodeError:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON data")
            except Exception as e:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

print(f"Starting server at http://localhost:{PORT}")
print("Press Ctrl+C to stop")

# Create data directory if it doesn't exist
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Reuse address to prevent 'Address already in use' errors on restart
socketserver.TCPServer.allow_reuse_address = True

with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.shutdown()
