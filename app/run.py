#from parse import scan_path

#if __name__ == '__main__':
    #scan_path('logs')'''


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods
    allow_headers=["*"], # Allows all headers
)


#upload route
@app.post("/api/upload")
async def upload_file():
    return {"message" : "hello server"}





