import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

@app.post('/api/upload')
async def upload(files: list[UploadFile] = File(...), rulesFile: UploadFile = File(...)):
    file_names = [file.filename for file in files]
    yara_file_name = rulesFile.filename
    return {
        'uploaded_files': file_names,
        'yara_file': yara_file_name
    }

@app.post('/api/detect')
async def detect():
    pass

if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8080)
