
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from fastapi import FastAPI


""" import custom modules  """
# from selection_tool.select_tool import get_tool

from routers import user_auth

app = FastAPI()
app.include_router(user_auth,prefix="/auth")





app.add_middleware \
(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("server start ...")

if __name__ == "__main__":
    uvicorn.run("app:app", reload=True)




