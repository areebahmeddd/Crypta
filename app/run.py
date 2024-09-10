import uvicorn
import os
from fastapi import FastAPI, File, UploadFile, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.parse import scan_path
from app.parse import find_type
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
async def upload(files: list[UploadFile] = File(...), rulesFile: UploadFile = File(...)):
    
    UPLOAD_DIR = "uploaded_files"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    #saving uploaded yara rules in a temp file
    results = []
    try:
        r'''with tempfile.NamedTemporaryFile(delete=False) as yara_rules_temp:
            yara_rules_path = yara_rules_temp.name
            yara_rules_temp.write(await rulesFile.read())''' 
        yara_rules_path = os.path.join(UPLOAD_DIR, rulesFile.filename)
        with open(yara_rules_path, "wb") as rules_file:
            rules_file.write(await rulesFile.read())
        print(yara_rules_path)
        

        #saving uploaded folders in a temp file    
        for file in files:
            file_path = os.path.join(UPLOAD_DIR, file.filename)
            with open(file_path, "wb") as f:
                f.write(await file.read())
            print(file_path) 
                
        #scanning the uploaded files with the uploaded rules
        #results = []
            file_type = find_type(file_path)
            if file_type == 'network':
                network_data = scan_network(file_path)
                results.append({
                    'file' : os.path.basename(file_path),
                    'protocol' : network_data
                })
                
            else:#file_type:
                scan_result = scan_path(file_path, yara_rules_path)
                if scan_result is None:
                    scan_result = {
                        'rule': 'No matches',
                        'component': 'N/A',
                        'context': 'N/A'
                    }
                results.append({
                    'file' : os.path.basename(file_path),
                    'rule' : scan_result['rule'],
                    'component' : scan_result['component'],
                    'context' : scan_result['context']
                })
                

        #backend response 
        return {"results": results}
    
    #handle the exception 
    except Exception as e:
        return {"error": str(e)}

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
