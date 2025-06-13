from flask import Flask, request, abort
import os
from datetime import datetime

UPLOAD_DIR = "received_results"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, 'Missing file')
    f = request.files['file']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f.filename or 'results.zip'
    save_path = os.path.join(UPLOAD_DIR, f"{timestamp}_{filename}")
    f.save(save_path)
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
