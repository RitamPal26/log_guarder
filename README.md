# LogGuarder

**LogGuarder** is a lightweight, security-focused log analysis utility built for Linux. It parses server authentication logs to detect potential security threats—specifically **Brute Force Attacks**—in real-time. Built with **Python**, it features a modular architecture, stateful analysis, and a professional terminal user interface using the `Rich` library.

## Key Features

* **Stateful Analysis:** Tracks IP behavior over time to identify repeated failures, not just isolated events.
* **Rich UI:** features a modern dashboard with color-coded alerts and summary tables.
* **Dual Logging:** simultaneously alerts the console (for the user) and writes to `security_events.log` (for auditing).
* **Zero Hardcoding:** Uses Regex with Named Groups for flexible parsing.
* **Linux Native:** Designed to work seamlessly with standard Linux log formats.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/RitamPal26/log_guarder.git
    cd log_guarder
    ```

2.  **Set up the Virtual Environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the utility by pointing it to a log file. You can use the provided sample data for testing.

```bash
python3 main.py samples/test_auth.log
```

**Output:**
The tool will stream the log analysis to your terminal. If an IP exceeds the failure threshold (default: 5), it will trigger a **[THREAT DETECTED]** alert.

To run on actual Linux system logs (requires permissions):

```bash
sudo python3 main.py /var/log/auth.log
```

## Design Choices & Architecture

This project follows a **Modular Design Pattern** to ensure readability and maintainability.

### 1. Separation of Concerns

Instead of a single script, the logic is split:

* **`parser/models.py`**: Uses Python `Dataclasses` to define a strict schema for log entries. This prevents data inconsistency.
* **`parser/engine.py`**: Handles the raw Regex logic. Isolated so the parsing rules can be updated without breaking the main app.
* **`main.py`**: Handles the CLI, file I/O, and alerting logic.

### 2. Regex with Named Groups

I used **Named Capture Groups** (e.g., `?P<ip>`) instead of positional indices (`group(1)`). It makes the code self-documenting. If the log format changes, I only need to update the Regex pattern, not the logic that accesses the data.

### 3. Stateful Analysis (O(1) Efficiency)

The tool uses a Hash Map (`collections.defaultdict`) to track failure counts. This ensures that looking up an IP address and incrementing its failure count remains an **O(1) constant time** operation, allowing the tool to handle large log files efficiently without slowing down.

### 4. User Experience (Rich Library)

I chose the **Rich** library over standard `print()` statements. Security tools are often monitored by humans. Color-coded alerts and structured tables allow operators to spot critical threats instantly, reducing "alert fatigue."

## Project Structure

```text
log_guarder/
├── samples/           # specific test data
├── parser/
│   ├── engine.py      # Core parsing logic
│   └── models.py      # Data structures
├── main.py            # Entry point & CLI
├── requirements.txt   # Dependencies
└── README.md          # Documentation
