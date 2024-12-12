# import pandas as pd
# import numpy as np
# import hashlib
# import random
# import string

# # Helper function to generate a random SHA256 hash
# def random_sha256():
#     random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
#     return hashlib.sha256(random_string.encode()).hexdigest()

# # Helper function to generate random market names
# def random_market():
#     markets = ["Google Play", "Amazon Appstore", "APKPure", "Third-Party Store"]
#     return random.choice(markets)

# # Set number of rows
# num_rows = 1048576  # 2^20 rows

# # Generate synthetic data
# np.random.seed(42)  # For reproducibility
# data = {
#     "apk_size": np.random.randint(1e6, 1e8, num_rows),  # Random APK sizes between 1 MB and 100 MB
#     "dex_size": np.random.randint(1e5, 1e7, num_rows),  # Random DEX sizes between 100 KB and 10 MB
#     "vercode": np.random.randint(1, 200, num_rows),     # Random version codes between 1 and 200
#     "days_since_scan": np.random.randint(0, 365, num_rows),  # Random days since scan
#     "permissions_count": np.random.randint(1, 50, num_rows),  # Random number of permissions (1 to 50)
#     "dangerous_permissions_count": np.random.randint(0, 10, num_rows),  # Dangerous permissions (0 to 10)
#     "activities_count": np.random.randint(1, 100, num_rows),  # Random activities count (1 to 100)
#     "services_count": np.random.randint(0, 20, num_rows),     # Random services count (0 to 20)
#     "certificate_expired": np.random.choice([True, False], num_rows),  # Randomly True or False
#     "suspicious_api_calls": np.random.randint(0, 10, num_rows),  # Suspicious API calls (0 to 10)
#     "apk_hash_sha256": [random_sha256() for _ in range(num_rows)],  # Generate random SHA256 hashes
#     "market_name": [random_market() for _ in range(num_rows)],     # Random market names
#     "anomaly": np.random.choice([0, 1], num_rows, p=[0.9, 0.1])    # 10% anomalous, 90% normal
# }

# # Create a DataFrame
# df = pd.DataFrame(data)

# # Save to CSV
# df.to_csv("sample_dataset.csv", index=False)
# print("Dataset created and saved as 'sample_dataset.csv'")

import pandas as pd
import numpy as np

# Set the path to your dataset
DATASET_PATH = "synthetic_apk_dataset.csv"  # Replace with the actual path to your dataset

# Read the dataset
df = pd.read_csv(DATASET_PATH)

# Check the first few rows to understand the data structure
print("Original Dataset:")
print(df.head())

# Define conditions for identifying anomalies in the dataset
# For example, anomalies can be based on unusually high values in certain features

# Let's define a set of conditions for detecting anomalies:
df["anomaly"] = np.where(
    (df["apk_size"] > 50000000) |  # Example condition: unusually large APK size (greater than 50 MB)
    (df["dex_size"] > 10000000) |  # Example condition: unusually large DEX size (greater than 10 MB)
    (df["suspicious_api_calls"] > 10) |  # Example condition: high suspicious API calls (greater than 10)
    (df["activities_count"] > 100) |  # Example condition: unusually large number of activities (greater than 100)
    (df["services_count"] > 50),  # Example condition: unusually large number of services (greater than 50)
    1,  # Label as anomalous (1)
    0   # Label as normal (0)
)

# Verify the updated anomaly column
print("\nUpdated Dataset with Corrected Anomaly Column:")
print(df[["apk_size", "dex_size", "suspicious_api_calls", "activities_count", "services_count", "anomaly"]].head())

# Optionally, save the updated dataset to a new CSV file
UPDATED_DATASET_PATH = "updated_synthetic_apk_dataset.csv"
df.to_csv(UPDATED_DATASET_PATH, index=False)

print(f"\nUpdated dataset saved to: {UPDATED_DATASET_PATH}")
