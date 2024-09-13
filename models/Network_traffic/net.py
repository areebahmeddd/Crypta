import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.utils import to_categorical
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import socket
import struct
import joblib

# Define the mapping for counts
class_mapping = {
    6: 'DrDoS_SNMP',
    1: 'DrDoS_DNS',
    3: 'DrDoS_MSSQL',
    5: 'DrDoS_NetBIOS',
    10: 'UDP-lag',
    0: 'BENIGN',
    8: 'DrDoS_UDP',
    7: 'DrDoS_SSDP',
    2: 'DrDoS_LDAP',
    9: 'Syn',
    4: 'DrDoS_NTP'
}

# Function to predict the network traffic
def predict_network(data):
  model=joblib.load('ML/Network_traffic/net.bin')
  data=ipl(data)
  pred=model.predict(data)
  ans=[class_mapping[i] for i in pred ]
  return ans

# Function to convert IP to integer
def ip_to_int(ip):
    if isinstance(ip, int): # Check if the IP is already an integer
        return ip             # Return as is
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0] # Convert to integer if it's a string
    except OSError:
        return 0 # Return 0 if the IP is invalid
    
# Function to preprocess the data
def ipl(data):
  data[' Source IP'] = data[' Source IP'].apply(ip_to_int)
  data[' Destination IP'] = data[' Destination IP'].apply(ip_to_int)
  data[' Timestamp'] = pd.to_datetime(data[' Timestamp'])
  data[' Timestamp'] = data[' Timestamp'].astype('int64') // 10**6
  return data


data = pd.read_csv('network1%.csv')
data[' Source IP'] = data[' Source IP'].apply(ip_to_int)
data[' Destination IP'] = data[' Destination IP'].apply(ip_to_int)
data[' Timestamp'] = pd.to_datetime(data[' Timestamp'])
# Convert the datetime to UNIX time (seconds since 1970-01-01)
data[' Timestamp'] = data[' Timestamp'].astype('int64') // 10**6  # Convert nanoseconds to seconds

sampled_df = data.sample(frac=1).reset_index(drop=True)

#preprocess the data
X = sampled_df[[' Source IP',' Source Port',' Destination IP',' Destination Port',' Protocol',' Timestamp',' Flow Duration',' Total Fwd Packets', ' Total Backward Packets']]
y = sampled_df[' Label']
X = X.values.reshape(-1, X.shape[1], 1)  # Reshape for CNN input

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#reshape X_train to 2D
X_train = X_train.reshape(X_train.shape[0], -1)
X_test= X_test.reshape(X_test.shape[0], -1)

# Create a random forest classifier
model= RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)
accuracyt = accuracy_score(y_test, y_pred)
print(" Accuracy Test:", accuracyt)

#joblib.dump(model, '/content/drive/MyDrive/networkanalysis.pkl')

new_data = pd.read_csv('network1%.csv') # Load the new data csv file without labels
#order of the columns is Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets
predictions = predict_network(new_data)
print(predictions)