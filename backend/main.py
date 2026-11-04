import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from backend.routes import router as routes_v2
from backend.text_service import TextClassifierService

app = FastAPI(
    title="Sanket (संकेत • સંકેત) API",
    description="Multilingual Digital Safety & Cyber Threat Indicator Platform (En/Hi/Gu)"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register v2 safety routes
app.include_router(routes_v2)

text_service = TextClassifierService()

class CheckRequest(BaseModel):
    text: str

class CheckResponse(BaseModel):
    risk_level: str
    explanation: str

INDEX_HTML_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))

@app.get("/", response_class=HTMLResponse)
def root():
    """Serves the interactive Sanket Web UI dashboard."""
    if os.path.exists(INDEX_HTML_PATH):
        return FileResponse(INDEX_HTML_PATH)
    return HTMLResponse("<h2>Sanket API is running. UI file frontend/index.html not found.</h2>")

@app.post("/check", response_model=CheckResponse)
def check_message(request: CheckRequest):
    """Production endpoint powered by Multilingual NLP & URL fusion."""
    res = text_service.inspect_message(request.text)
    return CheckResponse(
        risk_level=res["risk_level"],
        explanation=res["explanation_en"]
    )

