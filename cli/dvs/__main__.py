#!/usr/bin/env python3
import asyncio
import sys
from termcolor import colored
from .dashboard import start_dashboard
from .utils.loadProjectFiles import load_project_files

def main():
    if len(sys.argv) < 2:
        print(colored("Usage: dvs <command>", "red"))
        print("Available commands: scan, info, error")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "scan":
        print(colored("Running scan...", "blue"))
        try:
            # Start the dashboard with async support
            asyncio.get_event_loop().run_until_complete(start_dashboard())
        except KeyboardInterrupt:
            print("\nScan stopped")
        except Exception as e:
            print(colored(f"Error during scan: {str(e)}", "red"))
            sys.exit(1)
    elif command == "info":
        print(colored("=== System Information ===", "yellow"))
        print(colored(f"Python version: {sys.version}", "cyan"))
        print(colored(f"Platform: {sys.platform}", "cyan"))
        print(colored("Thanks for using this CLI!", "magenta"))
    elif command == "error":
        print(colored("This is an error message!", "red", attrs=["bold"]), file=sys.stderr)
    else:
        print(colored(f"Unknown command: {command}", "red"))
        sys.exit(1)

if __name__ == "__main__":
    main()