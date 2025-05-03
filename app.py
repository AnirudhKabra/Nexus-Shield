from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)

# Load a pre-trained machine learning model
model = joblib.load("malware_model.pkl")

@app.route('/', methods=['GET'])
def index():
    with open('index.html', 'r') as f:
        return f.read()

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if not all(key in data for key in ['hash', 'time']):
        return jsonify({"error": "Missing required fields (hash, time)"}), 400

    hash_value = data['hash']
    time = data['time']
    hash_len = len(hash_value)

    try:
        prediction = model.predict([[hash_len, time]])[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    result = {
        "prediction": "Malware" if prediction == 1 else "Not Malware"
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run()

    