#!/usr/bin/env python3
"""
CTF-Toolkit Management CLI

This script provides command-line management utilities for the CTF-Toolkit.
"""

import click
import os
import subprocess
import sys
from config import Config, get_config


@click.group()
@click.version_option(version='1.0.0', prog_name='CTF-Toolkit')
def cli():
    """CTF-Toolkit Management CLI"""
    pass


@cli.command()
@click.option('--host', default=None, help='Host to bind to')
@click.option('--port', default=None, type=int, help='Port to listen on')
@click.option('--debug/--no-debug', default=None, help='Enable debug mode')
@click.option('--env', type=click.Choice(['development', 'production', 'testing']),
              default='default', help='Configuration environment')
def run(host, port, debug, env):
    """Run the Flask application"""
    config = get_config(env)

    # Override with CLI arguments if provided
    if host:
        config.FLASK_HOST = host
    if port:
        config.FLASK_PORT = port
    if debug is not None:
        config.FLASK_DEBUG = debug

    click.echo(f"Starting CTF-Toolkit on {config.FLASK_HOST}:{config.FLASK_PORT}")
    click.echo(f"Debug mode: {config.FLASK_DEBUG}")
    click.echo(f"Environment: {env}")

    # Run the application
    os.environ['FLASK_ENV'] = env
    subprocess.run([sys.executable, 'app.py'])


@cli.command()
def test():
    """Run the test suite"""
    click.echo("Running tests...")
    result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-v'])
    sys.exit(result.returncode)


@cli.command()
@click.option('--coverage', is_flag=True, help='Run with coverage report')
def test_coverage(coverage):
    """Run tests with coverage report"""
    if coverage:
        click.echo("Running tests with coverage...")
        result = subprocess.run([
            sys.executable, '-m', 'pytest', 'tests/',
            '--cov=.', '--cov-report=html', '--cov-report=term'
        ])
    else:
        click.echo("Running tests...")
        result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-v'])

    sys.exit(result.returncode)


@cli.command()
def config_show():
    """Show current configuration"""
    Config.print_config()


@cli.command()
@click.option('--check-only', is_flag=True, help='Only check, don\'t create')
def init_dirs(check_only):
    """Initialize required directories"""
    directories = [
        Config.TOOLS_FOLDER,
        Config.UPLOAD_FOLDER,
        Config.DOWNLOAD_FOLDER,
        Config.LOG_DIR
    ]

    click.echo("Checking directories...")

    for directory in directories:
        exists = os.path.exists(directory)
        status = "✓" if exists else "✗"
        click.echo(f"{status} {directory}")

        if not exists and not check_only:
            os.makedirs(directory, exist_ok=True)
            click.echo(f"  → Created")

    if not check_only:
        click.echo("\nAll directories initialized!")


@cli.command()
def clean_logs():
    """Clean old log files"""
    import glob

    log_pattern = os.path.join(Config.LOG_DIR, '*.log*')
    log_files = glob.glob(log_pattern)

    if not log_files:
        click.echo("No log files found.")
        return

    click.echo(f"Found {len(log_files)} log file(s)")

    if click.confirm('Do you want to delete all log files?'):
        for log_file in log_files:
            try:
                os.remove(log_file)
                click.echo(f"Deleted: {log_file}")
            except Exception as e:
                click.echo(f"Error deleting {log_file}: {e}", err=True)

        click.echo("Log files cleaned!")
    else:
        click.echo("Cancelled.")


@cli.command()
@click.option('--port', default=443, type=int, help='Port to listen on')
def shell_listen(port):
    """Start a shell listener"""
    click.echo(f"Starting shell listener on port {port}...")
    subprocess.run([sys.executable, 'shell.py', str(port)])


@cli.command()
def docker_build():
    """Build Docker image"""
    click.echo("Building Docker image...")
    result = subprocess.run(['docker', 'build', '-t', 'ctf-toolkit:latest', '.'])

    if result.returncode == 0:
        click.echo("✓ Docker image built successfully!")
    else:
        click.echo("✗ Docker build failed!", err=True)
        sys.exit(1)


@cli.command()
def docker_run():
    """Run with Docker Compose"""
    click.echo("Starting CTF-Toolkit with Docker Compose...")
    subprocess.run(['docker-compose', 'up', '-d'])
    click.echo("✓ CTF-Toolkit is running!")
    click.echo("Access it at: http://localhost:5000")


@cli.command()
def docker_stop():
    """Stop Docker containers"""
    click.echo("Stopping CTF-Toolkit...")
    subprocess.run(['docker-compose', 'down'])
    click.echo("✓ CTF-Toolkit stopped!")


@cli.command()
def docker_logs():
    """Show Docker logs"""
    subprocess.run(['docker-compose', 'logs', '-f'])


@cli.command()
@click.option('--output', '-o', default='requirements.txt', help='Output file')
def freeze(output):
    """Generate requirements.txt from current environment"""
    click.echo(f"Generating {output}...")

    with open(output, 'w') as f:
        subprocess.run([sys.executable, '-m', 'pip', 'freeze'], stdout=f)

    click.echo(f"✓ Requirements saved to {output}")


@cli.command()
def lint():
    """Run code linters"""
    click.echo("Running flake8...")
    subprocess.run([sys.executable, '-m', 'flake8', '.', '--exclude=.venv,venv'])

    click.echo("\nRunning black (check only)...")
    subprocess.run([sys.executable, '-m', 'black', '.', '--check', '--exclude=.venv'])


@cli.command()
def format_code():
    """Format code with black"""
    click.echo("Formatting code with black...")
    result = subprocess.run([sys.executable, '-m', 'black', '.', '--exclude=.venv'])

    if result.returncode == 0:
        click.echo("✓ Code formatted successfully!")
    else:
        click.echo("✗ Formatting failed!", err=True)


@cli.command()
def security_scan():
    """Run security scanners"""
    click.echo("Running bandit security scanner...")
    subprocess.run([sys.executable, '-m', 'bandit', '-r', '.', '-x', './.venv'])

    click.echo("\nRunning safety check...")
    subprocess.run([sys.executable, '-m', 'safety', 'check'])


if __name__ == '__main__':
    cli()
