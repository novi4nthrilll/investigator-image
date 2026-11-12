"""Terminal Presentation and Forensic Report Renderer using Rich.
"""

from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


def print_tamper_report(result: Dict[str, Any]) -> None:
    """Renders a comprehensive, cyber-forensic terminal report."""
    info = result["image_info"]
    score = result["overall_score"]
    verdict = result["verdict"]
    color = result["risk_color"]
    
    # 1. Header Banner
    banner_text = Text()
    banner_text.append("🔍 INVESTIGATOR ", style="bold bright_cyan")
    banner_text.append("| Forensic Image Tampering & Manipulation Hunter\n", style="bold white")
    banner_text.append("Target: ", style="dim")
    banner_text.append(f"{info['file_name']}", style="bold yellow")
    banner_text.append(f" ({info['dimensions'][0]}x{info['dimensions'][1]} px, {info['format']}, {round(info['file_size_bytes']/1024, 1)} KB)", style="dim")
    console.print(Panel(banner_text, box=box.ROUNDED, border_style="bright_blue"))
    
    # 2. Forensic Metadata & Integrity Table
    meta_table = Table(title="🛡️ Chain of Custody & File Hashes", box=box.SIMPLE_HEAVY, show_header=True)
    meta_table.add_column("Property", style="cyan", width=18)
    meta_table.add_column("Forensic Value", style="white")
    
    meta_table.add_row("SHA-256", f"[bold green]{info['hashes']['sha256']}[/bold green]")
    meta_table.add_row("MD5", info['hashes']['md5'])
    meta_table.add_row("Color Mode", info['mode'])
    meta_table.add_row("Absolute Path", info['file_path'])
    console.print(meta_table)
    console.print()
    
    # 3. Overall Verdict Gauge
    score_bar_filled = int(score / 5)
    score_bar_empty = 20 - score_bar_filled
    bar_str = "█" * score_bar_filled + "░" * score_bar_empty
    
    verdict_panel_content = Text()
    verdict_panel_content.append(f"VERDICT: {verdict}\n", style=f"bold {color}")
    verdict_panel_content.append(f"Tampering Probability: [{bar_str}] {score}%\n\n", style=f"bold {color}")
    
    for finding in result["findings"]:
        verdict_panel_content.append(f"  • {finding}\n", style="white")
        
    console.print(Panel(verdict_panel_content, title="[bold]Diagnostic Assessment[/bold]", border_style=color, box=box.DOUBLE))
    console.print()
    
    # 4. Detailed Module Analysis Breakdown Table
    mod = result["modules"]
    breakdown_table = Table(title="🔬 Detailed Diagnostic Modules", box=box.ROUNDED)
    breakdown_table.add_column("Module", style="bold bright_cyan", width=24)
    breakdown_table.add_column("Score", justify="center", width=12)
    breakdown_table.add_column("Status / Findings", style="white")
    
    # ELA Row
    ela = mod["ela"]
    ela_status = f"{ela['anomalous_blocks']} anomalous blocks ({ela['anomaly_pct']}% area)"
    ela_style = "red" if ela["score"] > 50 else ("yellow" if ela["score"] > 25 else "green")
    breakdown_table.add_row("Error Level (ELA)", f"[{ela_style}]{ela['score']}%[/{ela_style}]", ela_status)
    
    # Noise Row
    noise = mod["noise"]
    noise_status = f"{noise['anomalous_blocks']} deviant variance regions (median var: {noise['median_variance']})"
    noise_style = "red" if noise["score"] > 50 else ("yellow" if noise["score"] > 25 else "green")
    breakdown_table.add_row("Sensor Noise Residual", f"[{noise_style}]{noise['score']}%[/{noise_style}]", noise_status)
    
    # Copy Move Row
    cm = mod["copy_move"]
    cm_status = f"Detected: {cm['detected']} ({cm['matches_count']} clone matches, {len(cm['clusters'])} shift vectors)"
    cm_style = "red" if cm["detected"] else "green"
    breakdown_table.add_row("Copy-Move (Cloning)", f"[{cm_style}]{cm['score']}%[/{cm_style}]", cm_status)
    
    console.print(breakdown_table)
    
    # 5. Output Artifact notification
    if result.get("heatmap_path"):
        console.print(f"\n[bold green]✓ Forensic Heatmap Artifact exported:[/bold green] [underline]{result['heatmap_path']}[/underline]")
    console.print()

