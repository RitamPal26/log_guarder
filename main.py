import sys
from collections import defaultdict
from parser.engine import parse_line

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_log> [threshold]")
        sys.exit(1)

    log_file = sys.argv[1]
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    
    failed_attempts = defaultdict(int)
    total_processed = 0

    print(f"--- Analyzing {log_file} (Threshold: {threshold}) ---")

    try:
        with open(log_file, "r") as f:
            for line in f:
                entry = parse_line(line)
                if not entry:
                    continue
                
                total_processed += 1
                
                if entry.status.lower() == "failed":
                    failed_attempts[entry.ip_address] += 1
                    
                    if failed_attempts[entry.ip_address] == threshold:
                        print(f"[ALERT] High failure rate detected from {entry.ip_address}!")

        print("\n--- Security Summary ---")
        print(f"Total entries processed: {total_processed}")
        
        flagged = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
        
        if flagged:
            print(f"Top Offenders (>= {threshold} failures):")
            for ip, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {ip}: {count} attempts")
        else:
            print("No suspicious activity detected.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
