import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load pre-trained components
model = joblib.load("anomaly_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
imputer = joblib.load("imputer.pkl")

# Simulated metrics for the About Page
accuracy = 0.85 
classification_report_data = {
    "Precision": [0.90, 0.39],
    "Recall": [0.93, 0.31],
    "F1-Score": [0.92, 0.34],
    "Support": [183554, 26161]
}
labels = ["Normal", "Anomalous"]

# Confusion matrix (simulated example)
confusion_matrix_data = np.array([[110, 10], [5, 25]])

# Streamlit Navigation Sidebar
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "About"])

# Home Page
if page == "Home":
    st.title("APK Anomaly Detection")
    st.write("Welcome to the APK Anomaly Detection dashboard.")
    st.write("Upload APK files to analyze anomalies and generate reports.")
    st.write("Use the navigation bar to explore more features.")

# About Page
elif page == "About":
    st.title("About the Model")
    st.write("### Model Information")
    st.write("- **Algorithm**: Isolation Forest")
    st.write("- **Purpose**: Detect anomalies in APK files based on extracted features.")
    st.write("- **Training Data**: Synthetic dataset with extracted APK features.")

    st.write("### Model Performance")
    st.write(f"- **Accuracy**: {accuracy * 100:.2f}%")

    # Classification Report
    st.write("#### Classification Report")
    classification_df = pd.DataFrame(classification_report_data, index=labels)
    st.dataframe(classification_df)

    # Confusion Matrix
    st.write("#### Confusion Matrix")
    st.write(f"Confusion Matrix:")
    st.write(pd.DataFrame(confusion_matrix_data, index=["Normal", "Anomalous"], columns=["Normal", "Anomalous"]))

    # Heatmap for Confusion Matrix
    st.write("### Confusion Matrix Heatmap")
    import seaborn as sns
    import matplotlib.pyplot as plt

    plt.figure(figsize=(5, 4))
    sns.heatmap(confusion_matrix_data, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    st.pyplot(plt)
