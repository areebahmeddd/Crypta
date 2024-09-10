import uvicorn
import os
from fastapi import FastAPI, File, UploadFile, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.parse import scan_file, find_type
from app.network import scan_network
from app.live import scan_drive

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

@app.post('/api/upload')
async def upload(uploadedFiles: list[UploadFile] = File(...), yaraFile: UploadFile = File(...)):
    
    UPLOAD_DIR = "uploaded_files"
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    results = []
    try:
        # Saving uploaded YARA rules in a temp file
        yara_rules_path = os.path.join(UPLOAD_DIR, yaraFile.filename)
        with open(yara_rules_path, "wb") as rules_file:
            rules_file.write(await yaraFile.read())
        print(yara_rules_path)

        # Saving uploaded files in a temp directory    
        for file in uploadedFiles:
            file_path = os.path.join(UPLOAD_DIR, file.filename)
            file_path = os.path.normpath(file_path) 
            print(file_path) 

            directory = os.path.dirname(file_path)
            if not os.path.exists(directory):
                os.makedirs(directory)
            
            with open(file_path, "wb") as f:
                f.write(await file.read())
            print(file_path) 

            # Scanning the uploaded files with the uploaded rules
            file_type = find_type(file_path)
            if file_type == 'network':
                network_data = scan_network(file_path)
                results.append({
                    'file': os.path.basename(file_path),
                    'protocol': network_data
                })
                
            else:  # Handle other file types
                scan_result = scan_file(file_path, yara_rules_path, file_type)
                if not scan_result:
                    # If no matches, return 'No matches'
                    scan_result = [{
                        'rule': 'No matches',
                        'component': 'N/A',
                        'content': 'N/A'
                    }]
                for match in scan_result:
                    results.append({
                        'file': os.path.basename(file_path),
                        'rule': match['rule'],
                        'component': match['component'],
                        'content': match['content']
                    })
                
        # Return results as a JSON response
        return JSONResponse(content=results)
    
    # Handle exceptions
    except Exception as e:
        return JSONResponse(content={"error": str(e)})

@app.post('/api/detect')
async def detect(background_tasks: BackgroundTasks):
    background_tasks.add_task(scan_drive)
    return JSONResponse(content={'message': 'Drive detection started.'})

@app.get('/api/files')
async def files():
    found_files = scan_drive()
    return JSONResponse(content=found_files)

if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8000)
