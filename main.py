import sys
from parser.engine import parse_line

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_log>")
        sys.exit(1)

    log_file = sys.argv[1]

    try:
        with open(log_file, "r") as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    # Basic formatted output
                    print(f"[{entry.timestamp}] {entry.status.upper()}: {entry.username} from {entry.ip_address}")
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()