import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from app.parse import scan_path
from app.parse import find_type
from app.network import scan_network
import os
import tempfile


app = FastAPI()
origins = [
    '*'
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

@app.post('/api/upload')
async def upload(files: list[UploadFile] = File(...), rulesFile: UploadFile = File(...)):
    
    #saving uploaded yara rules in a temp file
    results = []
    try:
        with tempfile.NamedTemporaryFile(delete=False) as yara_rules_temp:
            yara_rules_path = yara_rules_temp.name
            yara_rules_temp.write(await rulesFile.read())
        
        # Check if the file was created
        if not os.path.isfile(yara_rules_path):
            return {"error": "Yara rules file not created"}

        #saving uploaded folders in a temp file    
        uploaded_file_paths = []
        for file in files:
            with tempfile.NamedTemporaryFile(delete=False) as file_temp:
                file_path = file_temp.name
                file_temp.write(await file.read())
                uploaded_file_paths.append(file_path)
       
        # Check if the uploaded files were created
        for path in uploaded_file_paths:
            if not os.path.isfile(path):
                return {"error": f"Uploaded file not created: {path}"}
        
        #scanning the uploaded files with the uploaded rules
        #results = []
        for file_path in uploaded_file_paths:
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
async def detect():
    pass

if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8000)
