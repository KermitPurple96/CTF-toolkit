import subprocess
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIRECTORIES = ["templates", "static"]

class RestartFlaskOnChange(FileSystemEventHandler):
    def __init__(self, command):
        # Security: Use list instead of string for subprocess
        self.command = command if isinstance(command, list) else command.split()
        self.process = self.start_flask()

    def start_flask(self):
        # Security: shell=False prevents command injection
        return subprocess.Popen(self.command, shell=False)

    def on_any_event(self, event):
        if event.is_directory:
            return
        if any(event.src_path.startswith(dir) for dir in WATCH_DIRECTORIES):
            print(f"\n🔄 Cambio detectado en: {event.src_path}")
            # Properly terminate process
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = self.start_flask()

def main():
    # Security: Use list instead of string for command
    command = ['flask', 'run', '--host=0.0.0.0', '--port=5001',
               '--no-debugger', '--no-reload']

    event_handler = RestartFlaskOnChange(command)
    observer = Observer()

    for directory in WATCH_DIRECTORIES:
        observer.schedule(event_handler, path=directory, recursive=True)

    observer.start()

    print(f"👀 Observando carpetas: {', '.join(WATCH_DIRECTORIES)}...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        # Properly terminate process
        event_handler.process.terminate()
        try:
            event_handler.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            event_handler.process.kill()
            event_handler.process.wait()
    observer.join()

if __name__ == "__main__":
    main()

