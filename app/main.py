"""
AEGIS — AI Ethics & Governance Intelligence System
FastAPI Application Entry Point

This is the main entry point that:
- Initializes the FastAPI application
- Configures CORS
- Registers all API routes
- Handles startup/shutdown lifecycle
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
import os
import base64
import json
import sys
from datetime import datetime

if __package__:
    from .config import settings
    from .database import init_db, close_db, async_session_maker
    from .security import ensure_default_admin_user
else:
    # Support direct execution: `python app/main.py`
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from app.config import settings
    from app.database import init_db, close_db, async_session_maker
    from app.security import ensure_default_admin_user


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Runs on startup and shutdown.
    """
    # Startup
    print(f"🚀 Starting {settings.app_name} v{settings.app_version}")
    
    # Initialize database
    await init_db()
    print("✅ Database initialized")

    # Ensure default admin user from env exists
    async with async_session_maker() as session:
        await ensure_default_admin_user(session)
        await session.commit()
    print("✅ Admin bootstrap checked")

    yield
    
    # Shutdown
    print(f"🛑 Shutting down {settings.app_name}")
    await close_db()
    print("✅ Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="""
    **AEGIS** — AI Ethics & Governance Intelligence System

    A unified AI governance platform that automates risk scoring,
    enforces policy guardrails in real-time, and provides
    tamper-evident audit trails.
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/swagger",
    redoc_url="/redoc",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Import and register routes
if __package__:
    from .routes import filter, risk, policies, audit, redteam, dashboard, playbook, proxy, analyze, auth, logs
else:
    from app.routes import filter, risk, policies, audit, redteam, dashboard, playbook, proxy, analyze, auth, logs

app.include_router(filter.router, prefix=settings.api_v1_prefix, tags=["Guardrails"])
app.include_router(risk.router, prefix=settings.api_v1_prefix, tags=["Risk Scoring"])
app.include_router(policies.router, prefix=settings.api_v1_prefix, tags=["Policies"])
app.include_router(audit.router, prefix=settings.api_v1_prefix, tags=["Audit"])
app.include_router(redteam.router, prefix=settings.api_v1_prefix, tags=["Red Team"])
app.include_router(dashboard.router, prefix=settings.api_v1_prefix, tags=["Dashboard"])
app.include_router(playbook.router, prefix=settings.api_v1_prefix, tags=["Playbooks"])
app.include_router(proxy.router, prefix=settings.api_v1_prefix, tags=["Proxy"])
app.include_router(analyze.router, prefix=settings.api_v1_prefix, tags=["Analyze"])
app.include_router(auth.router, prefix=settings.api_v1_prefix, tags=["Auth"])
app.include_router(logs.router, prefix=settings.api_v1_prefix, tags=["Logs"])


@app.get("/", tags=["Frontend"])
async def serve_frontend():
    """Serve the frontend UI."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "healthy",
        "docs": "/docs",
    }


@app.get("/auth", tags=["Frontend"])
async def serve_auth_frontend():
    """Serve separate authentication page."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    auth_path = os.path.join(static_dir, "auth.html")
    return FileResponse(auth_path, media_type="text/html")


@app.get("/docs", tags=["Documentation"])
async def serve_docs():
    """Serve the architecture documentation page."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    docs_path = os.path.join(static_dir, "docs.html")
    return FileResponse(docs_path, media_type="text/html")


@app.get("/logs", tags=["Frontend"])
async def serve_logs_frontend():
    """Serve admin-only telemetry logs page."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    logs_path = os.path.join(static_dir, "logs.html")
    return FileResponse(logs_path, media_type="text/html")


@app.get("/deploy_code", tags=["Deployment"])
async def serve_deploy_code():
    """
    Generate and serve a Windows PowerShell script that extracts the entire AEGIS codebase.
    
    Download this file and run it on any Windows machine to extract all project files.
    
    Usage:
    1. Download the .ps1 file
    2. Open PowerShell
    3. Run: .\\aegis_extract.ps1
    """
    # Files to include
    FILES_TO_INCLUDE = [
        "app/__init__.py",
        "app/main.py",
        "app/config.py",
        "app/database.py",
        "app/models.py",
        "app/schemas.py",
        "app/engines/__init__.py",
        "app/engines/inference_providers.py",
        "app/engines/guardrails.py",
        "app/engines/risk_scorer.py",
        "app/engines/policy_engine.py",
        "app/engines/audit_vault.py",
        "app/engines/redteam_kit.py",
        "app/engines/playbook_runner.py",
        "app/engines/region_policies.py",
        "app/routes/__init__.py",
        "app/routes/filter.py",
        "app/routes/risk.py",
        "app/routes/policies.py",
        "app/routes/audit.py",
        "app/routes/redteam.py",
        "app/routes/dashboard.py",
        "app/routes/playbook.py",
        "app/routes/proxy.py",
        "app/routes/analyze.py",
        "app/static/index.html",
        "app/static/auth.html",
        "app/static/logs.html",
        "app/static/app.css",
        "app/static/config.js",
        "app/static/docs.html",
        "app/patterns/pii_patterns.json",
        "app/patterns/prompt_patterns.json",
        "app/patterns/code_patterns.json",
        "app/yara_rules/injection.yar",
        "app/yara_rules/jailbreak.yar",
        "app/yara_rules/pii.yar",
        "requirements.txt",
        ".env.example",
    ]
    
    backend_dir = os.path.dirname(__file__)
    base_dir = os.path.dirname(backend_dir)  # backend/
    
    # Collect files
    files_data = {}
    for rel_path in FILES_TO_INCLUDE:
        full_path = os.path.join(base_dir, rel_path.replace("/", os.sep))
        if os.path.exists(full_path):
            with open(full_path, "rb") as f:
                content = f.read()
            files_data[rel_path] = base64.b64encode(content).decode("utf-8")
    
    # Generate PowerShell script
    json_data = json.dumps(files_data)
    b64_json = base64.b64encode(json_data.encode("utf-8")).decode("utf-8")
    
    script = f'''# AEGIS Windows Extraction Script
# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Run this script in PowerShell to extract the AEGIS project files
#
# Usage:
#   1. Save this file as aegis_extract.ps1
#   2. Open PowerShell
#   3. cd to desired directory
#   4. Run: .\\aegis_extract.ps1
#

param(
    [string]$OutputDir = ".\\aegis"
)

Write-Host "=== AEGIS Windows Extraction Script ===" -ForegroundColor Cyan
Write-Host "Extracting to: $OutputDir" -ForegroundColor Yellow

# Create output directory
if (Test-Path $OutputDir) {{
    Write-Host "Directory exists, removing old files..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutputDir
}}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Base64 encoded JSON containing all files
$base64Data = @"
{b64_json}
"@

Write-Host "Decoding files..." -ForegroundColor Green

# Decode and parse JSON
$jsonBytes = [System.Convert]::FromBase64String($base64Data)
$jsonString = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
$filesDict = $jsonString | ConvertFrom-Json

# Extract each file
$fileCount = 0
foreach ($property in $filesDict.PSObject.Properties) {{
    $relPath = $property.Name
    $b64Content = $property.Value
    
    # Convert to Windows path
    $winPath = $relPath -replace "/", "\\\\"
    $fullPath = Join-Path $OutputDir $winPath
    
    # Create directory if needed
    $dir = Split-Path $fullPath -Parent
    if (-not (Test-Path $dir)) {{
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }}
    
    # Decode and write file
    $content = [System.Convert]::FromBase64String($b64Content)
    [System.IO.File]::WriteAllBytes($fullPath, $content)
    
    $fileCount++
    Write-Host "  Extracted: $relPath" -ForegroundColor DarkGray
}}

Write-Host ""
Write-Host "=== Extraction Complete ===" -ForegroundColor Green
Write-Host "Files extracted: $fileCount" -ForegroundColor Cyan
Write-Host "Location: $((Resolve-Path $OutputDir).Path)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. cd $OutputDir"
Write-Host "  2. pip install -r requirements.txt"
Write-Host "  3. uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
Write-Host ""
'''
    
    return Response(
        content=script,
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=aegis_extract.ps1"
        }
    )


@app.get("/config.js", tags=["Frontend"])
async def serve_config():
    """Serve frontend config with correct backend URL."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    config_path = os.path.join(static_dir, "config.js")
    return FileResponse(config_path, media_type="application/javascript")


@app.get("/app.css", tags=["Frontend"])
async def serve_app_css():
    """Serve bundled UI styles (no external CDN)."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    css_path = os.path.join(static_dir, "app.css")
    return FileResponse(css_path, media_type="text/css")


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "database": "connected",
        "cache": "memory",
    }


@app.get("/config", tags=["Health"])
async def frontend_config():
    """Expose non-sensitive config for frontend consumption."""
    return {
        "api_base": f"http://{settings.backend_host}:{settings.backend_port}",
        "api_prefix": settings.api_v1_prefix,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=False,
    )
