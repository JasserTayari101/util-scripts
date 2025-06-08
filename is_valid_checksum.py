import hashlib
import threading
import itertools
import sys
import time

def is_valid_checksum(file_path, expected_checksum):
    """Check if the file at file_path has a valid checksum."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to avoid memory issues with big files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest() == expected_checksum
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return False
    except Exception as e:
        print(f"An error: {e}")
        return False

def loader(stop_event):
    for symbol in itertools.cycle(['|', '/', '-', '\\']):
        if stop_event.is_set():
            break
        sys.stdout.write(f'\rPrüfe Datei... {symbol}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python is_valid_checksum.py <file_path> <expected_checksum>")
        sys.exit(1)

    file_path = sys.argv[1]
    expected_checksum = sys.argv[2]

    stop_event = threading.Event()  
    loader_thread = threading.Thread(target=loader, args=(stop_event,))
    loader_thread.start()

    valid = is_valid_checksum(file_path, expected_checksum)

    stop_event.set() 
    loader_thread.join()

    if valid:
        print("Die Datei hat eine gültige Checksum.")
        sys.exit(0)
    else:
        print("Die Datei hat KEINE gültige Checksum.")
        sys.exit(1)