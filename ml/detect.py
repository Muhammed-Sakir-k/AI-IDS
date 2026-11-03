import joblib
import pandas as pd

# Load trained model and label map
model = joblib.load("dataset/models/ids_model.pkl")
label_mapping = joblib.load("dataset/models/label_mapping.pkl")


def predict_traffic(flow_duration,
                    total_fwd_packets,
                    total_backward_packets,
                    flow_bytes_per_sec,
                    flow_packets_per_sec):

    # Ignore tiny flows — not enough data
    if total_fwd_packets < 50:
        return "BENIGN"

    features = pd.DataFrame([{
        "Flow Duration": flow_duration,
        "Total Fwd Packets": total_fwd_packets,
        "Total Backward Packets": total_backward_packets,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec
    }])

    prediction_code = model.predict(features)[0]

    # Get the real label name e.g. "PortScan", "DDoS", "BENIGN"
    label = label_mapping.get(prediction_code, "UNKNOWN")

    return label