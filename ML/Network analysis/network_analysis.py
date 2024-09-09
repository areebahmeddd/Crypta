from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import tensorflow as tf
import numpy as np
import pandas as pd
import warnings

# Make prediction for a row
def predict(row_value):
    # load the model
    model = tf.keras.models.load_model('Network analysis/hybrid_model.h5')
    # Convert to numpy array and ensure float32 type
    row_value = np.array(row_value).astype(np.float32)
    # Make prediction
    prediction = model.predict(np.expand_dims(row_value, axis=0))
    predicted_class = class_names[int(tf.round(prediction)[0])]
    return predicted_class

class_names = ['Normal', 'Attack']
warnings.filterwarnings('ignore')
df1=pd.read_csv('Network analysis/CTU13_Attack_Traffic-2.csv')
df2=pd.read_csv('Network analysis/CTU13_Normal_Traffic.csv')

# combine df1 and df2 and make it a dataset as test and train for binary classification and shuffle
df = pd.concat([df1, df2], ignore_index=True)
df = df.sample(frac=1).reset_index(drop=True)

X_train, X_val, y_train, y_val = train_test_split(
    df.drop('Label', axis=1).values, df['Label'].values, test_size=0.2
)

X_train = np.array(X_train).astype(np.float32)
X_val = np.array(X_val).astype(np.float32)
y_train = np.array(y_train).astype(np.float32)
y_val = np.array(y_val).astype(np.float32)

# A hybrid cnn, lstm model
model_hybrid = tf.keras.Sequential([
  tf.keras.layers.Reshape((X_train.shape[1], 1), input_shape=(X_train.shape[1],)),
  tf.keras.layers.Conv1D(32, 3, activation='relu'),
  tf.keras.layers.MaxPooling1D(2),
  tf.keras.layers.LSTM(64, return_sequences=True),
  tf.keras.layers.LSTM(32),
  tf.keras.layers.Dense(1, activation='sigmoid')
])

model_hybrid.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

history_hybrid = model_hybrid.fit(X_train,y_train, epochs=5, validation_data=(X_val,y_val))

# plot all histories accuracy and loss

plt.plot(history_hybrid.history['accuracy'], color='red')
plt.plot(history_hybrid.history['val_accuracy'], color='blue')
plt.title('Hybrid Model accuracy')
plt.ylabel('Accuracy')
plt.xlabel('Epoch')
plt.legend(['Train', 'Validation'], loc='upper left')
plt.show()

plt.plot(history_hybrid.history['loss'], color='red')
plt.plot(history_hybrid.history['val_loss'], color='blue')
plt.title('Hybrid Model loss')
plt.ylabel('loss')
plt.xlabel('Epoch')
plt.legend(['Train', 'Validation'], loc='upper left')
plt.show()

# save the model
model_hybrid.save('hybrid_model.h5')
print(model_hybrid.summary())

# Make prediction for a row
row_value = df1.iloc[1].drop('Label') 
predicted_class = predict(row_value)
print(predicted_class)
