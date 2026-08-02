"""API mínima para solicitar explicaciones de hallazgos de seguridad."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
AI_API_KEY = os.getenv("AI_API_KEY", "")

app = FastAPI(
    title="AI Remediation API",
    description="Explicación educativa de hallazgos de seguridad con Ollama.",
    version="0.1.0",
)


class Finding(BaseModel):
    id: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    category: str = Field(min_length=1)
    component: str | None = None
    description: str = Field(min_length=1, max_length=4000)
    fixedVersion: str | None = None


class Remediation(BaseModel):
    findingId: str
    model: str
    explanation: str
    recommendation: str
    validation: str
    learningNote: str


def check_bearer_token(value: str | None) -> None:
    if not AI_API_KEY:
        raise HTTPException(status_code=503, detail="AI_API_KEY no configurada")
    if not value:
        raise HTTPException(status_code=401, detail="Bearer token no proporcionado")

    scheme, separator, token = value.partition(" ")
    if scheme.lower() != "bearer" or not separator or token.strip() != AI_API_KEY:
        raise HTTPException(status_code=401, detail="Bearer token no válido")


def create_prompt(finding: Finding) -> str:
    context = {
        "id": finding.id,
        "severity": finding.severity,
        "tool": finding.tool,
        "category": finding.category,
        "component": finding.component,
        "description": finding.description,
        "fixedVersion": finding.fixedVersion,
    }
    return (
        "Eres un asistente educativo de ciberseguridad. Explica este hallazgo "
        "para un alumno de Formación Profesional. No inventes datos y no "
        "apliques cambios. Devuelve exclusivamente un objeto JSON con estos "
        "campos: explanation, recommendation, validation y learningNote.\n\n"
        f"Hallazgo:\n{json.dumps(context, ensure_ascii=False, indent=2)}"
    )


def ask_ollama(finding: Finding) -> dict[str, str]:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": create_prompt(finding),
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }
    request = urllib.request.Request(
        f"{OLLAMA_URL.rstrip('/')}/api/generate",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            document: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise HTTPException(status_code=502, detail=f"Error consultando Ollama: {error}") from error

    raw_result = document.get("response")
    if not isinstance(raw_result, str):
        raise HTTPException(status_code=502, detail="Ollama no devolvió una respuesta válida")
    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=502, detail="La respuesta de Ollama no es JSON") from error

    required = ("explanation", "recommendation", "validation", "learningNote")
    if not isinstance(result, dict) or any(not str(result.get(field, "")).strip() for field in required):
        raise HTTPException(status_code=502, detail="La respuesta no tiene el formato esperado")
    return {field: str(result[field]).strip() for field in required}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "UP", "model": OLLAMA_MODEL}


@app.post("/api/v1/remediations", response_model=Remediation)
def create_remediation(
    finding: Finding,
    authorization: str | None = Header(default=None),
) -> Remediation:
    check_bearer_token(authorization)
    result = ask_ollama(finding)
    return Remediation(findingId=finding.id, model=OLLAMA_MODEL, **result)
