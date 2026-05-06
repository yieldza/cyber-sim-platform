"""FastAPI worker — file generation, hash mutation, polyglot conversion.

This worker is internal; the Node API gateway is the only public entry point.
A static API key (WORKER_API_KEY) gates every endpoint.
"""
from __future__ import annotations

import base64
import os
import secrets
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .converter import SUPPORTED_TARGETS, detect_format, polyglot_zip_pdf, rewrap_eicar
from .generators import (
    EICAR_STRING,
    com_file,
    dropper_ps1,
    dropper_py,
    dropper_sh,
    eicar_apk,
    eicar_docx,
    eicar_pdf,
    minimal_pe,
    raw_eicar,
)
from .hash_mutator import (
    MutationResult,
    append_hash,
    append_random,
    hashes,
    mutate_until_prefix,
    pad_to_length,
)
from .techniques import (
    RUNNABLE_EXECUTORS,
    SUPPORTED_SCRIPT_FORMATS,
    generate_script,
    get_technique,
    list_techniques,
    run_test,
)

API_KEY = os.environ.get("WORKER_API_KEY") or secrets.token_hex(32)
ARTIFACTS_DIR = os.environ.get("ARTIFACTS_DIR", "/app/artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

app = FastAPI(
    title="CSP Worker",
    description="EICAR-based file/hash/polyglot generator for blue-team detection testing.",
    version="0.1.0",
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")


FileType = Literal[
    "eicar", "com", "pe", "pdf", "apk", "docx",
    "dropper-ps1", "dropper-sh", "dropper-py",
]
GENERATORS = {
    "eicar": raw_eicar,
    "com": com_file,
    "pe": minimal_pe,
    "pdf": eicar_pdf,
    "apk": eicar_apk,
    "docx": eicar_docx,
    "dropper-ps1": dropper_ps1,
    "dropper-sh": dropper_sh,
    "dropper-py": dropper_py,
}


def _result(data: bytes) -> dict:
    return {
        "size": len(data),
        "hashes": hashes(data),
        "data_b64": base64.b64encode(data).decode("ascii"),
    }


# ---------- /healthz ----------
@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "supported": list(GENERATORS.keys())}


# ---------- /generate ----------
class GenerateRequest(BaseModel):
    file_type: FileType
    note: str | None = Field(default=None, max_length=500)


@app.post("/generate", dependencies=[Depends(require_api_key)])
def generate(req: GenerateRequest) -> dict:
    fn = GENERATORS[req.file_type]
    data = fn()
    return {"file_type": req.file_type, **_result(data)}


# ---------- /mutate ----------
class MutateRequest(BaseModel):
    data_b64: str
    operation: Literal["append_random", "append_hash", "pad", "until_prefix"]
    n: int | None = None
    algo: Literal["md5", "sha1", "sha256"] | None = None
    target_length: int | None = None
    target_prefix: str | None = None
    max_iterations: int | None = None


@app.post("/mutate", dependencies=[Depends(require_api_key)])
def mutate(req: MutateRequest) -> dict:
    try:
        data = base64.b64decode(req.data_b64, validate=True)
    except Exception as exc:
        raise HTTPException(400, f"invalid base64: {exc}") from exc

    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(413, "input too large (10MB max)")

    try:
        if req.operation == "append_random":
            res = append_random(data, n=req.n or 16)
        elif req.operation == "append_hash":
            res = append_hash(data, algo=req.algo or "sha256")
        elif req.operation == "pad":
            if not req.target_length:
                raise HTTPException(400, "target_length required for pad")
            res = pad_to_length(data, target_len=req.target_length)
        elif req.operation == "until_prefix":
            if not req.target_prefix:
                raise HTTPException(400, "target_prefix required")
            res = mutate_until_prefix(
                data,
                target_prefix=req.target_prefix,
                algo=req.algo or "sha256",
                max_iterations=req.max_iterations or 1_000_000,
            )
        else:
            raise HTTPException(400, "unknown operation")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(408, str(exc)) from exc

    return {
        "operation": req.operation,
        "iterations": res.iterations,
        "before": res.before,
        "after": res.after,
        "size": len(res.data),
        "data_b64": base64.b64encode(res.data).decode("ascii"),
    }


# ---------- /convert ----------
class ConvertRequest(BaseModel):
    target: FileType
    mode: Literal["rewrap", "polyglot"] = "rewrap"
    pdf_text: str | None = None


@app.post("/convert", dependencies=[Depends(require_api_key)])
def convert(req: ConvertRequest) -> dict:
    if req.target not in SUPPORTED_TARGETS:
        raise HTTPException(400, f"unsupported target: {req.target}")
    if req.mode == "rewrap":
        data = rewrap_eicar(req.target)
    else:
        data = polyglot_zip_pdf(pdf_text=req.pdf_text or "")
    return {
        "target": req.target,
        "mode": req.mode,
        "detected_as": detect_format(data),
        **_result(data),
    }


# ---------- /detect ----------
class DetectRequest(BaseModel):
    data_b64: str


@app.post("/detect", dependencies=[Depends(require_api_key)])
def detect(req: DetectRequest) -> dict:
    try:
        data = base64.b64decode(req.data_b64, validate=True)
    except Exception as exc:
        raise HTTPException(400, f"invalid base64: {exc}") from exc
    return {
        "format": detect_format(data),
        "size": len(data),
        "hashes": hashes(data),
        "contains_eicar": EICAR_STRING in data,
    }


# ---------- /techniques (catalog) ----------
def _technique_dict(t) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "tactic": t.tactic,
        "platforms": list(t.platforms),
        "description": t.description,
        "tests": [
            {
                "name": tt.name,
                "description": tt.description,
                "executor": tt.executor,
                "command": tt.command,
                "platforms": list(tt.platforms),
                "expected_signals": list(tt.expected_signals),
                "cleanup": tt.cleanup,
                "runnable_here": tt.executor in RUNNABLE_EXECUTORS,
            }
            for tt in t.tests
        ],
    }


@app.get("/techniques", dependencies=[Depends(require_api_key)])
def techniques_list() -> dict:
    items = [_technique_dict(t) for t in list_techniques()]
    return {"count": len(items), "techniques": items}


@app.get("/techniques/{technique_id}", dependencies=[Depends(require_api_key)])
def techniques_detail(technique_id: str) -> dict:
    t = get_technique(technique_id)
    if t is None:
        raise HTTPException(404, "technique not found")
    return _technique_dict(t)


# ---------- /technique/run ----------
class RunRequest(BaseModel):
    technique_id: str
    test_name: str
    timeout: int | None = None


@app.post("/technique/run", dependencies=[Depends(require_api_key)])
def technique_run(req: RunRequest) -> dict:
    try:
        result = run_test(req.technique_id, req.test_name, timeout=req.timeout or 10)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    return {
        "technique_id": result.technique_id,
        "test_name": result.test_name,
        "executor": result.executor,
        "command": result.command,
        "argv": list(result.argv),
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "truncated": result.truncated,
    }


# ---------- /technique/script ----------
class ScriptRequest(BaseModel):
    technique_id: str
    test_name: str


@app.post("/technique/script", dependencies=[Depends(require_api_key)])
def technique_script(req: ScriptRequest) -> dict:
    try:
        filename, mime, content = generate_script(req.technique_id, req.test_name)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    data_b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return {
        "filename": filename,
        "mime": mime,
        "size": len(content),
        "data_b64": data_b64,
        "supported_formats": list(SUPPORTED_SCRIPT_FORMATS),
    }


@app.exception_handler(Exception)
def _on_error(_, exc):  # noqa: ANN001
    return JSONResponse(status_code=500, content={"error": str(exc)})
