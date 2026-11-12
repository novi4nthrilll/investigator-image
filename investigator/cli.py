"""Command Line Interface for Investigator.
"""

import json
import os
import sys
import click

from investigator.modules.tamper.analyzer import TamperAnalyzer
from investigator.modules.stego.analyzer import StegoAnalyzer
from investigator.modules.ai_detect.analyzer import AIAuthenticator
from investigator.utils.reporting import print_tamper_report, print_stego_report, print_ai_report, console


@click.group()
@click.version_option(version="0.1.0", prog_name="investigator")
def main():
    """Investigator - Cyber-Forensic Digital Image Intelligence Suite."""
    pass


@main.command(name="tamper")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--output", "-o", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Path to save visual ELA/Noise anomaly heatmap overlay image.")
@click.option("--ela-quality", "-q", type=int, default=95, show_default=True,
              help="JPEG recompression quality for Error Level Analysis.")
@click.option("--ela-scale", "-s", type=int, default=15, show_default=True,
              help="Contrast enhancement multiplier for ELA difference visualization.")
@click.option("--json-output", "--json", is_flag=True, default=False,
              help="Output results as structured JSON (useful for automated pipelines/SIEM).")
def tamper_cmd(image_path: str, output: str, ela_quality: int, ela_scale: int, json_output: bool):
    """Analyze image for tampering, manipulation, splicing, noise anomalies, and cloning."""
    try:
        analyzer = TamperAnalyzer(ela_quality=ela_quality, ela_scale=ela_scale)
        with console.status("[bold green]Executing forensic tamper analysis...[/bold green]"):
            result = analyzer.analyze(image_path, output_heatmap=output)
            
        if json_output:
            # Strip non-serializable fields if any
            clean_result = dict(result)
            click.echo(json.dumps(clean_result, indent=2, default=str))
        else:
            print_tamper_report(result)
            
    except Exception as e:
        console.print(f"[bold red]Forensic analysis error:[/bold red] {e}", file=sys.stderr)
        sys.exit(1)


@main.command(name="stego")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--extract-dir", "-x", type=click.Path(file_okay=False, writable=True), default=None,
              help="Directory to carve and extract hidden trailing overlays or polyglot files.")
@click.option("--dump-lsb", "-d", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Path to dump and save LSB bitplane 0 visual inspection image.")
@click.option("--json-output", "--json", is_flag=True, default=False,
              help="Output results as structured JSON.")
def stego_cmd(image_path: str, extract_dir: str, dump_lsb: str, json_output: bool):
    """Scan image for steganography, polyglots, trailing bytes, and hidden malware payloads."""
    try:
        analyzer = StegoAnalyzer()
        with console.status("[bold magenta]Scanning for stego & malicious payloads...[/bold magenta]"):
            result = analyzer.analyze(
                image_path,
                extract_dir=extract_dir,
                dump_lsb_path=dump_lsb
            )
            
        if json_output:
            clean_result = dict(result)
            click.echo(json.dumps(clean_result, indent=2, default=str))
        else:
            print_stego_report(result)
            
    except Exception as e:
        console.print(f"[bold red]Steganography scan error:[/bold red] {e}", file=sys.stderr)
        sys.exit(1)


@main.command(name="ai")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--fft-dump", "-f", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Path to dump and save 2D FFT frequency magnitude spectrum image.")
@click.option("--extract-prompt", "-p", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Path to save extracted generation prompt / ComfyUI workflow JSON.")
@click.option("--json-output", "--json", is_flag=True, default=False,
              help="Output results as structured JSON.")
def ai_cmd(image_path: str, fft_dump: str, extract_prompt: str, json_output: bool):
    """Authenticate whether an image is AI-generated (Midjourney, DALL-E, SD, Flux) or real."""
    try:
        authenticator = AIAuthenticator()
        with console.status("[bold yellow]Analyzing frequency spectrum & AI provenance...[/bold yellow]"):
            result = authenticator.analyze(
                image_path,
                fft_dump_path=fft_dump,
                extract_prompt_path=extract_prompt
            )
            
        if json_output:
            clean_result = dict(result)
            click.echo(json.dumps(clean_result, indent=2, default=str))
        else:
            print_ai_report(result)
            
    except Exception as e:
        console.print(f"[bold red]AI authentication error:[/bold red] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

