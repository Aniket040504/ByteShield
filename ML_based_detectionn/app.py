import os
import gc
import time
import subprocess
import joblib
from flask import Flask, request, render_template
from feature_extraction import extract_features

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'ML_model', 'malwareclassifier-V2.pkl')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

model = joblib.load(MODEL_PATH)

ALLOWED_EXTENSIONS = {'dll', 'exe'}

print("Starting")
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ── ClamAV via subprocess (works on Windows without needing clamd daemon) ───
def scan_with_clamav(file_path):
    try:

        CLAMSCAN_PATH = r"C:\Program Files\clamav-1.5.2.win.x64\clamscan.exe"

        result = subprocess.run(
            [CLAMSCAN_PATH, '--no-summary', file_path],
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout.strip()
        if 'FOUND' in output:
            virus_name = output.split('FOUND')[0].split(':')[-1].strip()
            return f"MALICIOUS (Detected as: {virus_name})"
        elif result.returncode == 0:
            return "CLEAN (No known signatures found)"
        else:
            return f"Scan Error: {result.stderr.strip() or 'Unknown error'}"
    except FileNotFoundError:
        return "ClamAV not installed or not in PATH"
    except subprocess.TimeoutExpired:
        return "Scan Error: ClamAV timed out"
    except Exception as e:
        return f"Scan Error: {str(e)}"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    
    if 'file' not in request.files:
        return render_template('index.html', error="No file uploaded.")

    file = request.files['file']

    if file.filename == '':
        return render_template('index.html', error="No file selected.")

    if not allowed_file(file.filename):
        return render_template('index.html', error="Unsupported file type. Only .exe and .dll allowed.")

    clean_filename = file.filename.replace(' ', '_')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], clean_filename)
    file.save(file_path)
    print("2. File saved")

    result = None
    try:
        # Feature extraction
        print("3. Extracting features")
        print("File uploaded")
        print("Extracting features...")
        features = extract_features(file_path)
        print("Features extracted")
        print("4. Features extracted")

        # ML prediction
        print("5. Running ML prediction...")
        prediction = model.predict(features)
        # model.predict may return an array; get first element
        ml_result = prediction[0] if hasattr(prediction, '__iter__') else prediction
        print("6. Prediction complete")

        gc.collect()

        # ClamAV scan
        print("7. Running ClamAV...")
        clam_result = scan_with_clamav(file_path)
        print("8. ClamAV complete")

        print("9. Preparing result")

        result = {
            "type": "file",
            "prediction": ml_result,
            "clamav_result": clam_result,
            "file_name": file.filename
        }

    except Exception as e:
        result = {
            "type": "file",
            "prediction": "Error",
            "clamav_result": f"Analysis failed: {str(e)}",
            "file_name": file.filename
        }
    finally:
        # Wait briefly then delete - handles Windows file locking
        time.sleep(0.5)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass  # If deletion fails, it's not critical

    print("====================")
    print(result)
    print("====================")

    return render_template('result.html', result=result)


if __name__ == '__main__':
    app.run(port=5001, debug=False)
