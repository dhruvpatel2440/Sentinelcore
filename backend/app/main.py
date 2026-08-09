from fastapi import FastAPI

from app.core.config import settings

app = FastAPI(title="SentinelCore API")


@app.get("/health")
def health():
    return {"status": "ok"}
