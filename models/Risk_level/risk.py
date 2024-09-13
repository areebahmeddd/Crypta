import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, SimpleRNN, Dense, Dropout
from tensorflow.keras.utils import to_categorical # Import to_categorical
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.layers import Bidirectional, LSTM
from sklearn.utils import class_weight
from sklearn.utils import shuffle


def predict_level(new_text):
    model=tf.keras.models.load_model('models/Risk_level/logsfinal95.h5')

    # Preprocess the input text
    new_sequence = tokenizer.texts_to_sequences([new_text])
    new_padded_sequence = pad_sequences(new_sequence, maxlen=max_sequence_length)
    prediction = model.predict(new_padded_sequence)
    # Get the predicted class
    predicted_class = np.argmax(prediction)
    # Get the original class name
    predicted_class_name = label_encoder.inverse_transform([predicted_class])[0]
    return predicted_class_name

class_names=['High','Low','Low to Medium','Medium']
# Load the dataset
risk=pd.read_csv('Risk_level/risktype.csv')
risk = shuffle(risk)
# Convert the Risk_Label to numerical values
label_encoder = LabelEncoder()
risk['Risk_Label'] =label_encoder.fit_transform(risk['Risk_Label'])

# Tokenize the Rule column
tokenizer = Tokenizer()
tokenizer.fit_on_texts(risk['Rule_Names'])
sequences = tokenizer.texts_to_sequences(risk['Rule_Names'])

# Pad the sequences to ensure equal length inputs for the RNN
max_sequence_length = max(len(seq) for seq in sequences)
X = pad_sequences(sequences, maxlen=max_sequence_length)

# Define the target variable
y = risk['Risk_Label']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Load GloVe Embeddings (you need to download the glove.6B.100d.txt file)
embeddings_index = {}
vocab_size = len(tokenizer.word_index) + 1  # +1 because of zero padding
embedding_dim = 100
with open('Risk_level/glove.6B.100d.txt') as f:
     for line in f:
         values = line.split()
         word = values[0]
         coefs = np.asarray(values[1:], dtype='float32')
         embeddings_index[word] = coefs

# # Create embedding matrix
embedding_matrix = np.zeros((vocab_size, embedding_dim))
for word, i in tokenizer.word_index.items():
     embedding_vector = embeddings_index.get(word)
     if embedding_vector is not None:
         embedding_matrix[i] = embedding_vector

# Modify embedding layer in the model to use pre-trained GloVe embeddings
# model.add(Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=max_sequence_length,
#                     weights=[embedding_matrix], trainable=False))
# Build the RNN model
model = Sequential()
model.add(Embedding(input_dim=vocab_size, output_dim=embedding_dim,
                    weights=[embedding_matrix], trainable=False))
# LSTM layer with dropout to avoid overfitting
model.add(LSTM(units=256, return_sequences=False))
model.add(Dropout(0.5))
  # Dropout for regularization

# Dense layers for classification
model.add(Dense(64, activation='relu'))
model.add(Dropout(0.5))  # Dropout for regularization
model.add(Dense(4, activation='softmax'))  # Softmax for multi-class classification

optimizer = Adam(learning_rate=5e-4)  # Try a slightly higher learning rate

# Compile the model
model.compile(optimizer=optimizer, loss='categorical_crossentropy', metrics=['accuracy'])

y_train = to_categorical(y_train, num_classes=4) # One-hot encode y_train
y_test = to_categorical(y_test, num_classes=4) # One-hot encode y_test

# Train the model with class weights
history = model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))
# Train the model

# Evaluate the model
loss,accuracy=model.evaluate(X_test,y_test)
# Save the model if needed
#model.save('/content/drive/MyDrive/logsfinal95.h5')

# Load the model
model=tf.keras.models.load_model('Risk_level/logsfinal95.h5')

# Make predictions
new_text = "Metadata_Manipulation"
predicted_class_name = predict_level(new_text)
print(f"Predicted class: {class_names[predicted_class_name]}")
