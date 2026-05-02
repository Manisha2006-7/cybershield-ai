import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

# Create directories if they don't exist
os.makedirs('data', exist_ok=True)
os.makedirs('model', exist_ok=True)

print("1. Generating synthetic NSL-KDD-like dataset for training...")
# For simplicity and immediate runnability, we use 5 key numerical features.
# In a real scenario, you would load NSL-KDD using pd.read_csv('data/KDDTrain+.txt')
np.random.seed(42)

# Generate Normal Traffic Data (800 records)
normal_data = pd.DataFrame({
    'duration': np.random.exponential(scale=2.0, size=800),
    'src_bytes': np.random.normal(loc=200, scale=50, size=800),
    'dst_bytes': np.random.normal(loc=3000, scale=500, size=800),
    'count': np.random.poisson(lam=5, size=800),
    'srv_count': np.random.poisson(lam=5, size=800)
})

# Generate Attack/Anomaly Traffic Data (200 records)
attack_data = pd.DataFrame({
    'duration': np.random.exponential(scale=50.0, size=200),
    'src_bytes': np.random.normal(loc=10000, scale=2000, size=200),
    'dst_bytes': np.random.normal(loc=10, scale=2, size=200),
    'count': np.random.poisson(lam=150, size=200),
    'srv_count': np.random.poisson(lam=150, size=200)
})

# Combine and save
df = pd.concat([normal_data, attack_data], ignore_index=True)
df.to_csv('data/synthetic_nsl_kdd.csv', index=False)
print("Dataset saved to data/synthetic_nsl_kdd.csv")

print("2. Preprocessing Data...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)

print("3. Training Isolation Forest Model...")
# Isolation Forest for anomaly detection
# contamination=0.2 because we know 20% (200/1000) are attacks
model = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
model.fit(X_scaled)

print("4. Saving Model and Scaler...")
with open('model/model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

print("Training Complete! Model and Scaler saved in the 'model/' directory.")