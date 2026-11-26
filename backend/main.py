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

# Register v2 safety routes under both /v2 and /api/v2
app.include_router(routes_v2)
app.include_router(routes_v2, prefix="/api")

text_service = TextClassifierService()

class CheckRequest(BaseModel):
    text: str

class CheckResponse(BaseModel):
    risk_level: str
    explanation: str

@app.post("/check", response_model=CheckResponse)
@app.post("/api/check", response_model=CheckResponse)
def check_message_legacy(request: CheckRequest):
    """Legacy endpoint support."""
    res = text_service.inspect_message(request.text)
    return CheckResponse(
        risk_level=res["risk_level"],
        explanation=res["explanation_en"]
    )

# Search across multiple potential root paths (local run, Docker, Vercel lambda)
POSSIBLE_HTML_PATHS = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "public", "index.html")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "static", "index.html")),
    os.path.abspath("frontend/index.html"),
    os.path.abspath("public/index.html"),
]

def get_index_html() -> str:
    for p in POSSIBLE_HTML_PATHS:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
    return "<h2>Sanket Platform is running. HTML dashboard file loading...</h2>"

@app.get("/", response_class=HTMLResponse)
def root():
    """Serves the interactive Sanket Web UI dashboard."""
    for p in POSSIBLE_HTML_PATHS:
        if os.path.exists(p):
            return FileResponse(p)
    return HTMLResponse(get_index_html())

@app.post("/check", response_model=CheckResponse)
def check_message(request: CheckRequest):
    """Production endpoint powered by Multilingual NLP & URL fusion."""
    res = text_service.inspect_message(request.text)
    return CheckResponse(
        risk_level=res["risk_level"],
        explanation=res["explanation_en"]
    )

