import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load the dataset
df = pd.read_csv('Malware_Deep.csv')

# Check the column names in the DataFrame
print(df.columns)

# Assuming the column names are 'hash', 'millisecond', and 'classification'
# Replace the column names accordingly
X = df[['hash', 'millisecond']].values
y = df['classification'].replace({'malware': 1, 'benign': 0}).values

# Train your RandomForestClassifier
model = RandomForestClassifier()
model.fit(X, y)

# Save the trained model
joblib.dump(model, 'malware_model.pkl')
