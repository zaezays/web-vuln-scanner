from app import create_app
import socket

def find_free_port(default=5001):
    """Check if default port is free, otherwise pick a random free port."""
    # Test if default is free
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
        if test_socket.connect_ex(('0.0.0.0', default)) != 0:
            # Default is free
            return default

    # Otherwise, let OS pick a free one
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 0))
        return s.getsockname()[1]

app = create_app()

if __name__ == "__main__":
    print("🚀 Flask is starting on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)

