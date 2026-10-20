#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_url_format, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, HEADERS, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()


def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]          Aragos - Form Grabber")
    console.print(f"[cyan]{bar}\n")


def extract_forms(url, timeout=DEFAULT_TIMEOUT):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for idx, form in enumerate(soup.find_all("form"), 1):
            action = form.get("action") or url
            full_action = urljoin(url, action)
            method = (form.get("method") or "GET").upper()
            enctype = form.get("enctype") or "application/x-www-form-urlencoded"
            inputs = []
            for tag in form.find_all(["input", "textarea", "select", "button"]):
                name = tag.get("name") or tag.get("id") or "(unnamed)"
                itype = tag.get("type") or tag.name
                autocomplete = tag.get("autocomplete", "default")
                inputs.append(f"{name} [{itype}]")
            csrf_present = any(
                "csrf" in (i.lower()) or "token" in (i.lower()) or "nonce" in (i.lower())
                for i in inputs
            )
            forms.append({
                "index": idx,
                "method": method,
                "action": full_action,
                "enctype": enctype,
                "fields": inputs,
                "csrf_protected": "Yes" if csrf_present else "No (WARN)",
            })
        return forms, resp.status_code
    except Exception as exc:
        return [], str(exc)


def run(target, threads=1, opts=None):
    opts = opts or {}
    banner()
    start = time.time()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    domain = clean_domain_input(target)
    url = ensure_url_format(target)
    if url.startswith("http://"):
        url = "https://" + domain

    console.print(f"[*] Inspecting forms on [cyan]{url}[/cyan] ...")
    forms, status = extract_forms(url, timeout=timeout)

    table = Table(title=f"Discovered HTML Forms – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("#", style="yellow", no_wrap=True)
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("Action URL", style="green", overflow="fold")
    table.add_column("Fields", style="white", overflow="fold")
    table.add_column("CSRF Token", style="magenta", no_wrap=True)

    if forms:
        for f in forms:
            table.add_row(
                str(f["index"]),
                f["method"],
                f["action"],
                ", ".join(f["fields"]) if f["fields"] else "None",
                f["csrf_protected"],
            )
    else:
        table.add_row("-", "INFO", url, f"No HTML <form> tags found (HTTP {status})", "OK")

    console.print(table)
    summary = f"Target: {domain} | Forms Found: {len(forms)} | Elapsed: {time.time() - start:.2f}s"
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Form Grabber analysis completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "form_grabber.txt"), export_console.export_text())


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
