from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Nirbhay API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequest(BaseModel):
    text: str

class CheckResponse(BaseModel):
    risk_level: str
    explanation: str

@app.get("/")
def root():
    return {"message": "Nirbhay API is running"}

@app.post("/check", response_model=CheckResponse)
def check_message(request: CheckRequest):
    # Placeholder logic — real classifier replaces this later
    red_flags = ["otp", "urgent", "verify", "blocked", "kyc", "click here"]
    text_lower = request.text.lower()
    matched = [flag for flag in red_flags if flag in text_lower]

    if matched:
        return CheckResponse(
            risk_level="suspicious",
            explanation=f"This message contains red-flag terms: {', '.join(matched)}."
        )
    return CheckResponse(
        risk_level="safe",
        explanation="No obvious scam indicators detected."
    )
