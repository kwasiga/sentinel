from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.database import init_db

app = FastAPI(title="Sentinel")


@app.on_event("startup")
def startup() -> None:
    init_db()


app.include_router(auth_router)
app.include_router(events_router)
app.include_router(incidents_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
