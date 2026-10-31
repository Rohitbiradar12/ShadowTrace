from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.services.auth import CurrentUser
from app.services.reports import incident_report

ROOT = Path(__file__).parent
templates = Environment(
    loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape(["html", "xml"])
)
router = APIRouter(include_in_schema=False)


@router.get("/")
@router.get("/login")
async def dashboard():
    return FileResponse(ROOT / "static" / "index.html", media_type="text/html")


@router.get("/reports/{alert_id}", response_class=HTMLResponse)
async def report_page(alert_id: str, principal: CurrentUser):
    try:
        report = await incident_report(alert_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return templates.get_template("report.html").render(
        report=report, author=principal.user.username
    )


@router.get("/api/v1/ui/reports/{alert_id}.json")
async def report_json(alert_id: str, principal: CurrentUser):
    try:
        report = await incident_report(alert_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return JSONResponse(
        report, headers={"Content-Disposition": 'attachment; filename="shadowtrace-incident.json"'}
    )
