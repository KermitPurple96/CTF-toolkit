import subprocess
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIRECTORIES = ["templates", "static"]

class RestartFlaskOnChange(FileSystemEventHandler):
    def __init__(self, command):
        self.command = command
        self.process = self.start_flask()

    def start_flask(self):
        return subprocess.Popen(self.command, shell=True)

    def on_any_event(self, event):
        if event.is_directory:
            return
        if any(event.src_path.startswith(dir) for dir in WATCH_DIRECTORIES):
            print(f"\n🔄 Cambio detectado en: {event.src_path}")
            self.process.kill()
            self.process = self.start_flask()

def main():
    # Cambiamos aquí para bindear en todas las interfaces (0.0.0.0)
    command = "flask run --host=0.0.0.0 --port=5001 --no-debugger --no-reload"
    
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
        event_handler.process.kill()
    observer.join()

if __name__ == "__main__":
    main()

