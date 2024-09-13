import os
import ast
import google.generativeai as genai
from google.generativeai import GenerativeModel
from dotenv import load_dotenv

# Load the API key from the .env file
load_dotenv()
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

# Generation settings to control the model's output
generation_config = {
    'temperature': 1,
    'top_p': 0.95,
    'top_k': 64,
    'max_output_tokens': 8192,
    'response_mime_type': 'text/plain'
}

# Safety settings to control the model's content filtering
safety_settings = [
    {'category': 'HARM_CATEGORY_HARASSMENT', 'threshold': 'BLOCK_NONE'},
    {'category': 'HARM_CATEGORY_HATE_SPEECH', 'threshold': 'BLOCK_NONE'},
    {'category': 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold': 'BLOCK_NONE'},
    {'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_NONE'}
]

# Load the instructions for the model
with open('metadata/instruction.md', 'r') as file:
    gemini_instructions = file.read()

# Initialize the Gemini model with custom settings and instructions
llm = GenerativeModel(
    model_name='gemini-1.5-flash-latest',
    generation_config=generation_config,
    safety_settings=safety_settings,
    system_instruction=gemini_instructions
)

# Start a chat session with the model
chat_session = llm.start_chat(history=[])

def predict(file_data):
    # Send the file data to the model for processing
    user_message = f'File Data: {file_data}'
    print('Sending to Gemini')
    bot_response = chat_session.send_message(user_message)
    # Filter the response to remove code formatting
    filtered_response = bot_response.text.replace('```python', '').replace('```', '')
    return ast.literal_eval(filtered_response)
