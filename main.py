import sys
import logging
from collections import defaultdict
from parser.engine import parse_line

LOG_OUTPUT_FILE = "security_events.log"
ALERT_THRESHOLD = 5

def setup_logger():
    """Configures logging to both file and console."""
    logger = logging.getLogger("LogGuarder")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_OUTPUT_FILE)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)

    console_handler = logging.StreamHandler()
    console_format = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_log>")
        sys.exit(1)

    log_file = sys.argv[1]
    
    logger = setup_logger()
    
    failed_attempts = defaultdict(int)
    
    logger.info(f"--- Starting analysis on: {log_file} ---")

    try:
        with open(log_file, "r") as f:
            for line in f:
                entry = parse_line(line)
                if not entry:
                    continue
                
                if entry.status.lower() == "failed":
                    failed_attempts[entry.ip_address] += 1
                    
                    if failed_attempts[entry.ip_address] == ALERT_THRESHOLD:
                        msg = f"[ALERT] Potential Brute Force: {entry.ip_address} hit {ALERT_THRESHOLD} failures!"
                        logger.warning(msg)

        logger.info("\n--- Analysis Complete ---")
        found_threats = False
        for ip, count in failed_attempts.items():
            if count >= ALERT_THRESHOLD:
                found_threats = True
                logger.error(f"THREAT DETECTED: {ip} ({count} failed attempts)")
        
        if not found_threats:
            logger.info("No major threats detected.")

    except FileNotFoundError:
        logger.critical(f"File not found: {log_file}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
