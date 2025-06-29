#!/usr/bin/env python3
"""
Convenient wrapper script to run the organized backend scripts using proper Python module execution.
"""
import sys
import subprocess
import os

def run_script(script_name):
    """Run a script using proper Python module execution."""
    
    # Map script names to their module paths (updated after cleanup)
    script_map = {
        'embedding_setup': '-m scripts.embedding_setup',
        'test_corrected_properties': '-m tests.test_corrected_properties',
        'start_api': '-m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000'
    }
    
    if script_name not in script_map:
        print(f"Unknown script: {script_name}")
        print("Available scripts:")
        for name in script_map.keys():
            print(f"  - {name}")
        return
    
    # Change to the backend directory to ensure proper module resolution
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    original_cwd = os.getcwd()
    os.chdir(backend_dir)
    
    # Set PYTHONPATH to current directory
    env = os.environ.copy()
    env['PYTHONPATH'] = backend_dir
    
    try:
        # Build the command
        module_args = script_map[script_name].split()
        cmd = [sys.executable] + module_args
        
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, env=env)
        
    except KeyboardInterrupt:
        print("\nScript interrupted by user")
    except Exception as e:
        print(f"Error running script: {e}")
    finally:
        # Restore original working directory
        os.chdir(original_cwd)

def install_package():
    """Install the package in development mode."""
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    original_cwd = os.getcwd()
    os.chdir(backend_dir)
    
    try:
        print("Installing package in development mode...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-e', '.'], check=True)
        print("✅ Package installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install package: {e}")
    finally:
        os.chdir(original_cwd)

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_scripts.py <command>")
        print("\nAvailable commands:")
        print("  install                     : Install the package in development mode")
        print("  embedding_setup             : Set up embeddings for CAPEC nodes")
        print("  test_corrected_properties   : Test corrected CAPEC properties")
        print("  start_api                   : Start the FastAPI server")
        print("\nFor first-time setup, run: python run_scripts.py install")
        return
    
    command = sys.argv[1]
    
    if command == 'install':
        install_package()
    elif command in ['embedding_setup', 'test_corrected_properties', 'start_api']:
        run_script(command)
    else:
        print(f"Unknown command: {command}")
        print("Run 'python run_scripts.py' to see available commands")

if __name__ == "__main__":
    main() 