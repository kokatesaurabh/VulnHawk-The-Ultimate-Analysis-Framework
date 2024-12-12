import os
import pandas as pd
import numpy as np
import joblib
import streamlit as st
from androguard.misc import AnalyzeAPK
from fpdf import FPDF
import hashlib
from datetime import datetime

# Helper function to calculate file hashes
def calculate_hash(file_path, hash_type="sha256"):
    hash_func = hashlib.new(hash_type)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Load the trained model, scaler, and imputer
model = joblib.load("anomaly_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
imputer = joblib.load("imputer.pkl")

# Streamlit App
st.title("APK Anomaly Detection with Real-Time Features")
uploaded_file = st.file_uploader("Upload an APK File", type=['apk'])

if uploaded_file:
    # Save the uploaded APK locally
    apk_path = f"temp_{uploaded_file.name}"
    with open(apk_path, "wb") as f:
        f.write(uploaded_file.read())

    # Analyze APK using Androguard
    apk, dex, analysis = AnalyzeAPK(apk_path)

    # Extract permissions
    permissions = apk.get_permissions()
    permissions_count = len(permissions)

    # Define a list of dangerous permissions
    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE"
    ]
    dangerous_permissions = [perm for perm in permissions if perm in DANGEROUS_PERMISSIONS]
    dangerous_permissions_count = len(dangerous_permissions)

    # Calculate days since current date for real-time feature
    current_date = datetime.now()
    scan_date = current_date.strftime("%Y-%m-%d")
    days_since_scan = 0  # For real-time scans, days since scan will be 0

    # Generate APK features
    apk_features = {
        "apk_size": os.path.getsize(apk_path),  # Actual APK size
        "dex_size": len(apk.get_dex()),         # DEX size
        "vercode": apk.get_androidversion_code(),  # Version code
        "activities_count": len(apk.get_activities()),  # Number of activities
        "services_count": len(apk.get_services()),      # Number of services
        "certificate_expired": np.random.choice([0, 1]),  # Simulated value for demonstration
        "suspicious_api_calls": np.random.randint(0, 10),  # Simulated value for demonstration
        "permissions_count": permissions_count,  # Total permissions
        "dangerous_permissions_count": dangerous_permissions_count,  # Dangerous permissions
        "days_since_scan": days_since_scan,  # Real-time scan feature
    }

    # Generate file hashes for the APK
    apk_features["sha256"] = calculate_hash(apk_path, "sha256")
    apk_features["sha1"] = calculate_hash(apk_path, "sha1")
    apk_features["md5"] = calculate_hash(apk_path, "md5")

    # Convert features to DataFrame for model input
    input_data = pd.DataFrame([apk_features])

    # Preprocess the input data
    input_data_scaled = scaler.transform(input_data[[ 
        "apk_size", "dex_size", "vercode", "activities_count",
        "services_count", "certificate_expired", "suspicious_api_calls",
        "permissions_count", "dangerous_permissions_count", "days_since_scan"
    ]])
    input_data_imputed = imputer.transform(input_data_scaled)

    # Predict anomaly status
    prediction = model.predict(input_data_imputed)
    anomaly_status = "Anomalous" if prediction[0] == -1 else "Normal"

    # Add anomaly detection result to features
    apk_features["anomaly_status"] = anomaly_status

    # Display results in Streamlit
    st.write("APK Details:")
    st.json({k: v for k, v in apk_features.items() if k not in ["permissions", "dangerous_permissions"]})

    st.write("Total Permissions:")
    st.write(f"Count: {permissions_count}")
    st.write("Names:")
    st.write("\n".join(permissions))

    st.write("Dangerous Permissions:")
    st.write(f"Count: {dangerous_permissions_count}")
    st.write("Names:")
    st.write("\n".join(dangerous_permissions))

    # Generate PDF Report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="APK Anomaly Detection Report", ln=True, align="C")
    pdf.ln(10)
    
    # Add APK Features to PDF
    for key, value in apk_features.items():
        if key == "permissions":
            pdf.cell(200, 10, txt="Permissions List:", ln=True)
            for perm in permissions:
                pdf.cell(200, 10, txt=f" - {perm}", ln=True)
        elif key == "dangerous_permissions":
            pdf.cell(200, 10, txt="Dangerous Permissions List:", ln=True)
            for perm in dangerous_permissions:
                pdf.cell(200, 10, txt=f" - {perm}", ln=True)
        else:
            pdf.cell(200, 10, txt=f"{key}: {value}", ln=True)
    
    # Add Total Permissions Details
    pdf.cell(200, 10, txt="Total Permissions List:", ln=True)
    for perm in permissions:
        pdf.cell(200, 10, txt=f" - {perm}", ln=True)

    pdf_path = f"{uploaded_file.name}_anomaly_report.pdf"
    pdf.output(pdf_path)

    # Download report in Streamlit
    with open(pdf_path, "rb") as f:
        st.download_button("Download Report", f, file_name=pdf_path)

    # Cleanup
    os.remove(apk_path)
    os.remove(pdf_path)