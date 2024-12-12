import os
import datetime
import pandas as pd
import joblib
from androguard.misc import AnalyzeAPK
import streamlit as st
import json

# Define a mapping of vulnerabilities to recommendations and CWE IDs
VULNERABILITY_MAPPING = {
    "Excessive Permissions": {
        "recommendation": "Review the requested permissions and remove those not essential for app functionality.",
        "cwe": "CWE-276"
    },
    "Dangerous Permissions": {
        "recommendation": "Minimize the use of permissions like READ_SMS, RECORD_AUDIO, etc., unless absolutely necessary.",
        "cwe": "CWE-264"
    },
    "Exported Activities/Services": {
        "recommendation": "Ensure exported components are secured with permissions or set 'exported=false'.",
        "cwe": "CWE-200"
    },
    "Large APK Size": {
        "recommendation": "Optimize APK size by removing unused resources and compressing assets.",
        "cwe": "CWE-409"
    },
    "Large DEX Size": {
        "recommendation": "Split large DEX files into smaller ones using multidex support.",
        "cwe": "CWE-789"
    },
}

# Function to detect vulnerabilities using Androguard
def detect_vulnerabilities(apk_details, permissions, apk):
    vulnerabilities = []

    # Excessive permissions
    if apk_details["Permissions"] > 50:
        vulnerabilities.append("Excessive Permissions")

    # Dangerous permissions
    dangerous_permissions = [
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
    dangerous_permissions_count = sum(1 for perm in permissions if perm in dangerous_permissions)
    if dangerous_permissions_count > 5:
        vulnerabilities.append("Dangerous Permissions")

    # Exported activities/services/providers
    for activity in apk.get_activities():
        if "exported=\"true\"" in activity:
            vulnerabilities.append("Exported Activities/Services")
    for service in apk.get_services():
        if "exported=\"true\"" in service:
            vulnerabilities.append("Exported Activities/Services")
    for provider in apk.get_providers():
        if "exported=\"true\"" in provider:
            vulnerabilities.append("Exported Activities/Services")

    # Large APK/DEX size
    if apk_details["APK Size"] > 50 * 1024 * 1024:  # Larger than 50 MB
        vulnerabilities.append("Large APK Size")
    if apk_details["DEX Size"] > 10 * 1024 * 1024:  # Larger than 10 MB
        vulnerabilities.append("Large DEX Size")

    return vulnerabilities

# Load trained ML model
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")
imputer = joblib.load("imputer.pkl")

# Streamlit UI
st.title("Static APK Vulnerability Analysis")
uploaded_file = st.file_uploader("Upload an APK File", type=['apk'])

if uploaded_file:
    try:
        # Save the uploaded APK locally
        apk_path = f"temp_{uploaded_file.name}"
        with open(apk_path, "wb") as f:
            f.write(uploaded_file.read())

        # Extract metadata using Androguard
        apk, dex, analysis = AnalyzeAPK(apk_path)
        permissions = apk.get_permissions()

        apk_details = {
            "File Name": uploaded_file.name,
            "Package Name": apk.get_package(),
            "Scan Date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "App Name": apk.get_app_name(),
            "Version Code": apk.get_androidversion_code(),
            "APK Size": os.path.getsize(apk_path),
            "DEX Size": len(apk.get_dex()),
            "Permissions": len(permissions),
            "Activities": len(apk.get_activities()),
            "Services": len(apk.get_services()),
            "Providers": len(apk.get_providers()),
            "Certificate Info": apk.get_signature_name(),
        }

        # Detect vulnerabilities
        vulnerabilities = detect_vulnerabilities(apk_details, permissions, apk)
        cwe_ids = [VULNERABILITY_MAPPING[vuln]["cwe"] for vuln in vulnerabilities if vuln in VULNERABILITY_MAPPING]
        recommendations = [VULNERABILITY_MAPPING[vuln]["recommendation"] for vuln in vulnerabilities if vuln in VULNERABILITY_MAPPING]

        # Generate input for ML model
        input_data = pd.DataFrame([{
            "apk_size": apk_details["APK Size"],
            "dex_size": apk_details["DEX Size"],
            "vercode": apk_details["Version Code"],
            "days_since_scan": 0  # Placeholder for now
        }])

        # Predict vulnerability and calculate security score
        prediction = model.predict(input_data)[0]
        security_score = model.predict_proba(input_data)[0][1] * 100

        # Add analysis results to the report
        apk_details["Vulnerable"] = "Yes" if prediction else "No"
        apk_details["Security Score"] = f"{security_score:.2f}"
        apk_details["Grade"] = "A" if security_score > 80 else "B" if security_score > 60 else "C"
        apk_details["Detected Vulnerabilities"] = vulnerabilities
        apk_details["Recommendations"] = recommendations
        apk_details["CWE IDs"] = cwe_ids
        apk_details["Vulnerability Count"] = len(vulnerabilities)

        # Display results in Streamlit
        st.write("APK Details:")
        st.json(apk_details)

        st.write(f"Total Vulnerabilities Detected: {len(vulnerabilities)}")  # Display count

        st.write("Permissions:")
        for perm in permissions:
            st.write(f"- {perm}")

        st.write("Vulnerabilities Detected:")
        for vuln in vulnerabilities:
            st.write(f"- {vuln}")

        st.write("Recommendations:")
        for rec in recommendations:
            st.write(f"- {rec}")

        st.write("CWE IDs:")
        for cwe in cwe_ids:
            st.write(f"- {cwe}")

        # Provide download button for report
        report_json = json.dumps(apk_details, indent=4)

        st.download_button(
            label="Download APK Analysis Report",
            data=report_json,
            file_name=f"{apk_details['File Name']}_report.json",
            mime="application/json"
        )

        # Cleanup
        os.remove(apk_path)

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")