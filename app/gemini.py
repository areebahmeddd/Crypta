import os
import ast
import google.generativeai as genai
from google.generativeai import GenerativeModel
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

# Load the API key from the .env file
load_dotenv()

gemini_api_key = os.getenv('GEMINI_API_KEY')
if gemini_api_key:
    print(f'GEMINI_API_KEY is set: {gemini_api_key}')
else:
    print('GEMINI_API_KEY is not set')
    
genai.configure(api_key=gemini_api_key)

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

def predict(file_data, prompt):
    # Send the file data to the model for analysis (Prompt: Analyse)
    user_message = f'Prompt: {prompt}\n{file_data}'
    print('Sending data to Gemini')
    bot_response = chat_session.send_message(user_message)
    # Filter the response to remove code formatting
    filtered_response = bot_response.text.replace('```python', '').replace('```', '')
    return ast.literal_eval(filtered_response)

def summarize(file_data, prompt):
    # Send the file data to the model for summarization (Prompt: Summarize)
    user_message = f'Prompt: {prompt}\n{file_data}'
    print('Generating summary with Gemini')
    bot_response = chat_session.send_message(user_message)

    # Generate a PDF report with the summary
    file_name = 'report.pdf'
    document = SimpleDocTemplate(file_name, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Add title to the report and create a new paragraph for each line of the summary
    title_style = styles['Title']
    story.append(Paragraph('Summary Report', title_style))
    story.append(Spacer(1, 12))

    # Define custom style for the content paragraphs
    content_style = styles['BodyText']
    content_style = ParagraphStyle(
        'Content',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=12,
        spaceAfter=12
    )

    # Split the response into paragraphs and add them to the report
    paragraphs = bot_response.text.split('\n')
    for para in paragraphs:
        story.append(Paragraph(para, content_style))

    # Build the PDF report with the summary content
    document.build(story)
    return file_name
