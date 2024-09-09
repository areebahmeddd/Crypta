import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from app.parse import scan_path
from app.parse import find_type
from app.network import scan_network
import os



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
        #direcly fetching yara rules
        yara_rules_path = await rulesFile.read()

        #directly fetching the uploaded files    
        for file in files:
            file_path = await file.read()
            
            #checking file type
            file_type = find_type(file.filename)

            #scanning network files
            if file_type == 'network':
                network_data = scan_network(file_path)
                results.append({
                    'file' : os.path.basename(file_path),
                    'protocol' : network_data
                })

            #scanning other file types    
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
