import uvicorn
import os
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from parse import scan_file, find_type
from network import scan_network
from drive import scan_drive

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

@app.post('/api/analyze')
async def analyze(uploadedFiles: list[UploadFile] = File(...), yaraFile: UploadFile = File(...)):
    # Initialize list to store scan results and create temporary directory
    scan_results = []
    TEMP_DIR = 'temp'
    os.makedirs(TEMP_DIR, exist_ok=True)

    try:
        # Save YARA rules file to temporary directory
        rules_path = os.path.join(TEMP_DIR, yaraFile.filename)
        with open(rules_path, 'wb') as f:
            f.write(await yaraFile.read())

        # Scan each uploaded file to temporary directory
        for file in uploadedFiles:
            file_path = os.path.normpath(os.path.join(TEMP_DIR, file.filename))
            file_directory  = os.path.dirname(file_path)
            os.makedirs(file_directory , exist_ok=True)

            with open(file_path, 'wb') as f:
                f.write(await file.read())

            # Determine file type and scan file based on type
            file_type = find_type(file_path)
            if file_type == 'network':
                network_data = scan_network(file_path)
                # Append network scan results to scan_results list as dictionary
                scan_results.append({
                    'file': os.path.basename(file_path),
                    'network': network_data
                })

            else:
                file_data = scan_file(file_path, rules_path, file_type)
                # Extend file scan results to scan_results list as dictionary for each file
                scan_results.extend({
                    'file': os.path.basename(file_path),
                    'rule': data['rule'],
                    'component': data['component'],
                    'content': data['content']
                } for data in file_data)

        return JSONResponse(content=scan_results)
    except Exception as e:
        return JSONResponse(content={'error': e})

@app.post('/api/detect')
async def detect(background_tasks: BackgroundTasks):
    # Add scan_drive function to background tasks to look for removable drives
    background_tasks.add_task(scan_drive)
    return JSONResponse(content={'message': 'Drive detection started.'})

@app.get('/api/files')
async def files():
    # Get metadata of all files in the drive
    files_metadata = scan_drive()
    return JSONResponse(content=files_metadata)

@app.get('/api/files/{file_name}')
async def send_file(file_name: str):
    # Send the file based on the file name in the request
    files_metadata = scan_drive()
    file_object = next(
        (file for file in files_metadata if file['name'] == file_name), None
    )
    return FileResponse(filename=file_object['name'], path=file_object['path'], media_type='application/octet-stream')

@app.post('/api/download')
async def download():
    pass

@app.post('/api/export')
async def export():
    pass

@app.post('/api/chat')
async def chat():
    pass

if __name__ == '__main__':
    uvicorn.run('run:app', host='127.0.0.1', port=8000, reload=True)
