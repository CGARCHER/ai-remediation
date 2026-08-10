"""API para generar remediaciones educativas revisables."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import PurePosixPath
from typing import Any, Literal
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
_gemini_models_value = (
    os.getenv("GEMINI_MODELS")
    or os.getenv("GEMINI_MODEL")
    or "gemini-3.5-flash-lite,gemini-3.1-flash-lite"
)
GEMINI_MODELS = tuple(
    dict.fromkeys(model.strip() for model in _gemini_models_value.split(",") if model.strip())
)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").strip().lower()
AI_API_KEY = os.getenv("AI_API_KEY", "")

SUPPORTED_PROVIDERS = {"ollama", "gemini"}
CONFIDENCE_LEVELS = {"LOW", "MEDIUM", "HIGH"}

app = FastAPI(
    title="AI Remediation API",
    description="Remediación educativa con Ollama o Gemini y revisión humana.",
    version="0.3.0",
)


class Finding(BaseModel):
    id: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    category: str = Field(min_length=1)
    component: str | None = None
    description: str = Field(min_length=1, max_length=4000)
    currentVersion: str | None = None
    fixedVersion: str | None = None
    affectedFile: str | None = None
    line: int | None = Field(default=None, ge=1)
    sourceContext: str | None = Field(default=None, max_length=8000)


class PatchProposal(BaseModel):
    available: bool
    file: str | None = None
    format: Literal["unified-diff", "none"] = "none"
    content: str | None = None
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    requiresHumanReview: bool = True
    reason: str | None = None


class Remediation(BaseModel):
    findingId: str
    provider: str
    model: str
    durationMs: int
    explanation: str
    recommendation: str
    patchProposal: PatchProposal
    validation: str
    learningNote: str
    warnings: list[str] = Field(default_factory=list)


REMEDIATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "explanation": {"type": "string"},
        "recommendation": {"type": "string"},
        "patchProposal": {
            "type": "object",
            "properties": {
                "available": {"type": "boolean"},
                "file": {"type": ["string", "null"]},
                "format": {"type": "string", "enum": ["unified-diff", "none"]},
                "content": {"type": ["string", "null"]},
                "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                "requiresHumanReview": {"type": "boolean"},
                "reason": {"type": ["string", "null"]},
            },
            "required": [
                "available",
                "file",
                "format",
                "content",
                "confidence",
                "requiresHumanReview",
                "reason",
            ],
        },
        "validation": {"type": "string"},
        "learningNote": {"type": "string"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "explanation",
        "recommendation",
        "patchProposal",
        "validation",
        "learningNote",
        "warnings",
    ],
}


def check_bearer_token(value: str | None) -> None:
    if not AI_API_KEY:
        raise HTTPException(status_code=503, detail="AI_API_KEY no configurada")
    if not value:
        raise HTTPException(status_code=401, detail="Bearer token no proporcionado")

    scheme, separator, token = value.partition(" ")
    if scheme.lower() != "bearer" or not separator or token.strip() != AI_API_KEY:
        raise HTTPException(status_code=401, detail="Bearer token no válido")


def resolve_provider(requested: str | None) -> str:
    provider = (requested or AI_PROVIDER).strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Proveedor de IA no válido")
    if provider == "gemini" and not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="GEMINI_API_KEY no configurada")
    return provider


def is_synthetic_finding(finding: Finding) -> bool:
    """Identifica los hallazgos creados para pruebas."""
    return finding.id.upper().startswith(("CVE-TEST-", "TEST-"))


def unavailable_patch(reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "file": None,
        "format": "none",
        "content": None,
        "confidence": "LOW",
        "requiresHumanReview": True,
        "reason": reason,
    }


def synthetic_remediation(finding: Finding) -> dict[str, Any]:
    return {
        "explanation": (
            f"El identificador {finding.id} parece corresponder a un hallazgo de prueba. "
            "No se puede confirmar que represente una vulnerabilidad real."
        ),
        "recommendation": (
            "No debe aplicarse una corrección basándose solamente en este identificador. "
            "Utiliza un hallazgo real generado por Semgrep, Dependency-Check o Trivy."
        ),
        "patchProposal": unavailable_patch(
            "Los hallazgos sintéticos no contienen evidencia para generar un parche."
        ),
        "validation": (
            "Sustituye el identificador de prueba por el hallazgo real y vuelve a ejecutar "
            "el analizador correspondiente."
        ),
        "learningNote": (
            "Los identificadores de prueba permiten comprobar la API, pero no justifican "
            "una modificación del proyecto."
        ),
        "warnings": ["No se ha consultado ningún modelo de IA."],
    }


def create_prompt(finding: Finding) -> str:
    context = finding.model_dump()
    return (
        "Eres un asistente educativo de ciberseguridad para alumnado de Formación "
        "Profesional. Interpreta el hallazgo y, cuando exista contexto suficiente, "
        "genera una propuesta de parche que una persona pueda revisar.\n\n"
        "El hallazgo puede proceder de SAST, SCA, análisis de contenedores o reglas "
        "de hardening. Adapta la remediación a su categoría.\n\n"
        "Reglas obligatorias:\n"
        "- Utiliza exclusivamente los datos recibidos.\n"
        "- No inventes archivos, etiquetas Docker, versiones, código ni comandos.\n"
        "- La propuesta nunca se aplica automáticamente.\n"
        "- Solo genera un parche si affectedFile y sourceContext permiten hacerlo.\n"
        "- Si no hay contexto suficiente, establece patchProposal.available en false "
        "y explica el motivo en reason.\n"
        "- Si hay parche, utiliza formato unified-diff y limita el cambio al archivo "
        "indicado en affectedFile.\n"
        "- Utiliza fixedVersion únicamente cuando esté presente.\n"
        "- Para SAST, corrige solo el fragmento relacionado con la regla.\n"
        "- Para SCA, propone el cambio de dependencia en pom.xml sin inventar versiones.\n"
        "- Para contenedores y hardening, limita el cambio a Dockerfile o Compose y "
        "advierte de posibles efectos funcionales.\n"
        "- La validación debe indicar cómo repetir las pruebas y el analizador.\n"
        "- Mantén explanation, recommendation y learningNote breves y didácticos.\n"
        "- Devuelve exclusivamente un objeto JSON que cumpla el esquema solicitado.\n\n"
        f"Hallazgo:\n{json.dumps(context, ensure_ascii=False, indent=2)}"
    )


def is_safe_relative_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(normalized) and not path.is_absolute() and ".." not in path.parts


def validate_result(result: Any) -> dict[str, Any]:
    required_text = ("explanation", "recommendation", "validation", "learningNote")
    if not isinstance(result, dict) or any(
        not isinstance(result.get(field), str) or not result[field].strip()
        for field in required_text
    ):
        raise HTTPException(status_code=502, detail="La respuesta no tiene el formato esperado")

    patch = result.get("patchProposal")
    if not isinstance(patch, dict) or not isinstance(patch.get("available"), bool):
        raise HTTPException(status_code=502, detail="La propuesta de parche no es válida")

    patch["requiresHumanReview"] = True
    patch["confidence"] = str(patch.get("confidence", "LOW")).upper()
    if patch["confidence"] not in CONFIDENCE_LEVELS:
        patch["confidence"] = "LOW"

    if patch["available"]:
        file = patch.get("file")
        content = patch.get("content")
        if not isinstance(file, str) or not is_safe_relative_path(file):
            raise HTTPException(status_code=502, detail="El parche contiene una ruta no válida")
        if not isinstance(content, str) or not content.strip() or len(content) > 12000:
            raise HTTPException(status_code=502, detail="El contenido del parche no es válido")
        patch["format"] = "unified-diff"
        patch["reason"] = None
    else:
        patch = unavailable_patch(str(patch.get("reason") or "Falta contexto para generar el parche."))

    warnings = result.get("warnings", [])
    if not isinstance(warnings, list):
        warnings = []

    return {
        **{field: result[field].strip() for field in required_text},
        "patchProposal": patch,
        "warnings": [str(item).strip() for item in warnings if str(item).strip()][:10],
    }


def parse_json_response(value: str) -> Any:
    """Interpreta JSON puro o incluido en un bloque Markdown."""
    text = value.strip()
    if text.startswith("```"):
        first_line, separator, remainder = text.partition("\n")
        if separator and first_line.lower() in {"```", "```json"}:
            text = remainder
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return json.loads(text.strip())


def ask_ollama(finding: Finding) -> tuple[dict[str, Any], int]:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": create_prompt(finding),
        "stream": False,
        "keep_alive": -1,
        "format": REMEDIATION_SCHEMA,
        "options": {
            "temperature": 0.1,
            "num_ctx": 2048,
            "num_predict": 450,
        },
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

    duration_ms = int(document.get("total_duration", 0) / 1_000_000)
    return validate_result(result), duration_ms


def ask_gemini(finding: Finding, model: str) -> tuple[dict[str, Any], int]:
    payload = {
        "contents": [{"role": "user", "parts": [{"text": create_prompt(finding)}]}],
        "generationConfig": {
            "maxOutputTokens": 2000,
            "thinkingConfig": {"thinkingLevel": "low"},
            "responseMimeType": "application/json",
            "responseJsonSchema": REMEDIATION_SCHEMA,
        },
    }
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{quote(model, safe='')}:generateContent"
    )
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": GEMINI_API_KEY},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            document: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise HTTPException(
            status_code=error.code,
            detail=f"Gemini ha rechazado la petición (HTTP {error.code})",
        ) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise HTTPException(status_code=502, detail=f"Error consultando Gemini: {error}") from error

    try:
        candidate = document["candidates"][0]
        parts = candidate["content"]["parts"]
        raw_result = "".join(
            part["text"]
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        )
        result = parse_json_response(raw_result)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        candidates = document.get("candidates")
        finish_reason = (
            candidates[0].get("finishReason", "desconocido")
            if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict)
            else "desconocido"
        )
        raise HTTPException(
            status_code=502,
            detail=f"Gemini no devolvió un JSON válido (motivo: {finish_reason})",
        ) from error

    duration_ms = int((time.perf_counter() - started) * 1000)
    return validate_result(result), duration_ms


def ask_gemini_with_fallback(
    finding: Finding,
) -> tuple[dict[str, Any], int, str, str]:
    """Prueba los modelos configurados y utiliza Ollama si no están disponibles."""
    recoverable_statuses = {429, 500, 502, 503, 504}
    started = time.perf_counter()

    for model in GEMINI_MODELS:
        try:
            result, _ = ask_gemini(finding, model)
            duration_ms = int((time.perf_counter() - started) * 1000)
            return result, duration_ms, "gemini", model
        except HTTPException as error:
            if error.status_code not in recoverable_statuses:
                raise

    try:
        result, _ = ask_ollama(finding)
    except HTTPException as error:
        raise HTTPException(
            status_code=502,
            detail="Los modelos de Gemini y el modelo local no están disponibles.",
        ) from error

    duration_ms = int((time.perf_counter() - started) * 1000)
    return result, duration_ms, "ollama", OLLAMA_MODEL


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "UP",
        "defaultProvider": AI_PROVIDER,
        "providers": {
            "ollama": {"available": True, "model": OLLAMA_MODEL},
            "gemini": {"available": bool(GEMINI_API_KEY), "models": list(GEMINI_MODELS)},
        },
    }


@app.post("/api/v1/remediations", response_model=Remediation)
def create_remediation(
    finding: Finding,
    provider: str | None = None,
    authorization: str | None = Header(default=None),
) -> Remediation:
    check_bearer_token(authorization)
    selected_provider = resolve_provider(provider)

    if is_synthetic_finding(finding):
        result = synthetic_remediation(finding)
        duration_ms = 0
        model = "synthetic"
    elif selected_provider == "gemini":
        result, duration_ms, selected_provider, model = ask_gemini_with_fallback(finding)
    else:
        result, duration_ms = ask_ollama(finding)
        model = OLLAMA_MODEL

    return Remediation(
        findingId=finding.id,
        provider=selected_provider,
        model=model,
        durationMs=duration_ms,
        **result,
    )
