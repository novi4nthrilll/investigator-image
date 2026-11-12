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


def print_stego_report(result: Dict[str, Any]) -> None:
    """Renders a comprehensive steganography and malicious payload audit report."""
    info = result["image_info"]
    score = result["overall_score"]
    verdict = result["verdict"]
    color = result["risk_color"]
    
    # 1. Header Banner
    banner_text = Text()
    banner_text.append("🕵️ STEGO & PAYLOAD ANALYZER ", style="bold bright_magenta")
    banner_text.append("| Malicious Concealment & Polyglot Hunter\n", style="bold white")
    banner_text.append("Target: ", style="dim")
    banner_text.append(f"{info['file_name']}", style="bold yellow")
    banner_text.append(f" ({info['dimensions'][0]}x{info['dimensions'][1]} px, {info['format']}, {round(info['file_size_bytes']/1024, 1)} KB)", style="dim")
    console.print(Panel(banner_text, box=box.ROUNDED, border_style="bright_magenta"))
    
    # 2. Forensic Metadata & Integrity Table
    meta_table = Table(title="🛡️ File Integrity & Hash Digest", box=box.SIMPLE_HEAVY, show_header=True)
    meta_table.add_column("Property", style="cyan", width=18)
    meta_table.add_column("Value", style="white")
    
    meta_table.add_row("SHA-256", f"[bold green]{info['hashes']['sha256']}[/bold green]")
    meta_table.add_row("MD5", info['hashes']['md5'])
    meta_table.add_row("Total File Size", f"{info['file_size_bytes']} bytes")
    console.print(meta_table)
    console.print()
    
    # 3. Overall Verdict Gauge
    score_bar_filled = int(score / 5)
    score_bar_empty = 20 - score_bar_filled
    bar_str = "█" * score_bar_filled + "░" * score_bar_empty
    
    verdict_panel_content = Text()
    verdict_panel_content.append(f"VERDICT: {verdict}\n", style=f"bold {color}")
    verdict_panel_content.append(f"Payload Concealment Risk: [{bar_str}] {score}%\n\n", style=f"bold {color}")
    
    for finding in result["findings"]:
        verdict_panel_content.append(f"  • {finding}\n", style="white")
        
    console.print(Panel(verdict_panel_content, title="[bold]Steganographic Threat Assessment[/bold]", border_style=color, box=box.DOUBLE))
    console.print()
    
    # 4. Detailed Module Analysis Breakdown Table
    mod = result["modules"]
    breakdown_table = Table(title="🔬 Steganography & Payload Vectors", box=box.ROUNDED)
    breakdown_table.add_column("Vector", style="bold bright_cyan", width=26)
    breakdown_table.add_column("Score", justify="center", width=12)
    breakdown_table.add_column("Detection Status / Signatures", style="white")
    
    # Overlay Row
    ov = mod["overlay"]
    ov_status = f"Trailing Bytes: {ov['trailing_bytes']} B (Entropy: {ov['entropy']}/8.0)"
    if ov["payloads"]:
        payload_names = ", ".join([p["type"] for p in ov["payloads"][:2]])
        ov_status += f" | Signatures: [bold red]{payload_names}[/bold red]"
    ov_style = "red" if ov["score"] > 50 else ("yellow" if ov["score"] > 20 else "green")
    breakdown_table.add_row("Trailing Bytes / Polyglot", f"[{ov_style}]{ov['score']}%[/{ov_style}]", ov_status)
    
    # LSB Row
    lsb = mod["lsb"]
    lsb_status = f"Avg Bit-0 Entropy: {lsb['avg_entropy']}/1.0 | Stego Prob: {round(lsb['stego_probability']*100, 1)}%"
    lsb_style = "red" if lsb["score"] > 50 else ("yellow" if lsb["score"] > 25 else "green")
    breakdown_table.add_row("LSB Bitplane Entropy", f"[{lsb_style}]{lsb['score']}%[/{lsb_style}]", lsb_status)
    
    # Metadata Row
    meta = mod["metadata"]
    meta_status = f"{len(meta['findings'])} suspicious finding(s) across {meta['tags_count']} tags/comments"
    meta_style = "red" if meta["score"] > 50 else ("yellow" if meta["score"] > 20 else "green")
    breakdown_table.add_row("EXIF / Metadata Payloads", f"[{meta_style}]{meta['score']}%[/{meta_style}]", meta_status)
    
    console.print(breakdown_table)
    
    # 5. Carved Artifacts Output
    if result.get("carved_files"):
        console.print("\n[bold green]📦 Extracted Carved Payloads:[/bold green]")
        for c in result["carved_files"]:
            console.print(f"  • [underline cyan]{c}[/underline cyan]")
            
    if result.get("dumped_lsb_path"):
        console.print(f"[bold green]✓ LSB Bitplane 0 Visualization dumped:[/bold green] [underline]{result['dumped_lsb_path']}[/underline]")
    console.print()


def print_ai_report(result: Dict[str, Any]) -> None:
    """Renders a comprehensive AI-generated and deepfake authenticity report."""
    info = result["image_info"]
    score = result["overall_score"]
    verdict = result["verdict"]
    color = result["risk_color"]
    
    # 1. Header Banner
    banner_text = Text()
    banner_text.append("🤖 AI & DEEPFAKE AUTHENTICATOR ", style="bold bright_yellow")
    banner_text.append("| Generative Model & Synthetic Media Auditor\n", style="bold white")
    banner_text.append("Target: ", style="dim")
    banner_text.append(f"{info['file_name']}", style="bold yellow")
    banner_text.append(f" ({info['dimensions'][0]}x{info['dimensions'][1]} px, {info['format']}, {round(info['file_size_bytes']/1024, 1)} KB)", style="dim")
    console.print(Panel(banner_text, box=box.ROUNDED, border_style="bright_yellow"))
    
    # 2. Forensic Metadata & Integrity Table
    meta_table = Table(title="🛡️ Digital Provenance & Cryptographic Signature", box=box.SIMPLE_HEAVY, show_header=True)
    meta_table.add_column("Property", style="cyan", width=22)
    meta_table.add_column("Value", style="white")
    
    meta_table.add_row("SHA-256", f"[bold green]{info['hashes']['sha256']}[/bold green]")
    meta_table.add_row("MD5", info['hashes']['md5'])
    meta_table.add_row("Container Dimensions", f"{info['dimensions'][0]} × {info['dimensions'][1]}")
    console.print(meta_table)
    console.print()
    
    # 3. Overall Verdict Gauge
    score_bar_filled = int(score / 5)
    score_bar_empty = 20 - score_bar_filled
    bar_str = "█" * score_bar_filled + "░" * score_bar_empty
    
    verdict_panel_content = Text()
    verdict_panel_content.append(f"VERDICT: {verdict}\n", style=f"bold {color}")
    verdict_panel_content.append(f"Synthetic Generation Probability: [{bar_str}] {score}%\n\n", style=f"bold {color}")
    
    for finding in result["findings"]:
        verdict_panel_content.append(f"  • {finding}\n", style="white")
        
    console.print(Panel(verdict_panel_content, title="[bold]Generative AI Assessment[/bold]", border_style=color, box=box.DOUBLE))
    console.print()
    
    # 4. Detailed Module Analysis Breakdown Table
    mod = result["modules"]
    breakdown_table = Table(title="🔬 AI Forensic Diagnostic Vectors", box=box.ROUNDED)
    breakdown_table.add_column("Vector", style="bold bright_cyan", width=26)
    breakdown_table.add_column("Score", justify="center", width=12)
    breakdown_table.add_column("Spectral / Provenance Findings", style="white")
    
    # FFT Row
    fft = mod["fft"]
    fft_status = f"{fft['peaks']} peaks ({fft['symmetrical_grid_peaks']} grid conjugate pairs) | Decay α: {fft['alpha_slope']} (MSE: {fft['radial_residual_mse']})"
    fft_style = "red" if fft["score"] > 50 else ("yellow" if fft["score"] > 25 else "green")
    breakdown_table.add_row("2D FFT Spectrum", f"[{fft_style}]{fft['score']}%[/{fft_style}]", fft_status)
    
    # Metadata Row
    meta = mod["metadata"]
    if meta["is_confirmed"]:
        meta_status = f"[bold red]Confirmed Generator:[/bold red] {meta['generator']} (Prompt Extracted: {meta['has_prompt']})"
        meta_style = "red"
    else:
        meta_status = "No synthetic generator signatures or C2PA AI claims found"
        meta_style = "green"
    breakdown_table.add_row("Provenance & C2PA", f"[{meta_style}]{meta['score']}%[/{meta_style}]", meta_status)
    
    # Chroma Row
    chroma = mod["chroma"]
    chroma_status = f"Extreme Saturation: {chroma['extreme_sat_pct']}% | Chroma Variance: {chroma['chroma_variance']}"
    chroma_style = "red" if chroma["score"] > 50 else ("yellow" if chroma["score"] > 25 else "green")
    breakdown_table.add_row("Chroma & Saturation", f"[{chroma_style}]{chroma['score']}%[/{chroma_style}]", chroma_status)
    
    console.print(breakdown_table)
    
    # 5. Output Artifact notification
    if result.get("fft_dump_path"):
        console.print(f"\n[bold green]✓ 2D FFT Magnitude Spectrum exported:[/bold green] [underline]{result['fft_dump_path']}[/underline]")
    if result.get("prompt_dump_path"):
        console.print(f"[bold green]✓ Extracted AI Generation Prompt exported:[/bold green] [underline]{result['prompt_dump_path']}[/underline]")
    console.print()



