# LogGuarder

**LogGuarder** is a lightweight, security-focused log analysis utility built for Linux. It parses server authentication logs to detect potential security threats—specifically **Brute Force Attacks**—in real-time. Built with **Python**, it features a modular architecture, stateful analysis, and a professional terminal user interface using the `Rich` library.

## Key Features

* **Stateful Analysis:** Tracks IP behavior over time to identify repeated failures, not just isolated events.
* **Rich UI:** features a modern dashboard with color-coded alerts and summary tables.
* **Dual Logging:** simultaneously alerts the console (for the user) and writes to `security_events.log` (for auditing).
* **Linux Native:** Designed to work seamlessly with standard Linux log formats.
* **Resilient Parsing:** Robust handling of edge cases, including malformed lines and UI injection attempts.

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

4.  **Generate Test Data:**
    The repository does not ship with log files. Generate them using the included script:
    ```bash
    python3 samples/populate_logs.py
    ```
    *This will create `samples/test_auth.log` with dummy data.*


## Usage

Run the utility by pointing it to a log file.

### Standard Analysis
```bash
python3 main.py samples/test_auth.log
```

*Defaults: Threshold = 5 failures.*

**Run on System Logs (Requires sudo):**

```bash
sudo python3 main.py /var/log/auth.log
```

## Testing

This project maintains **100% test coverage** using `pytest`. The test suite covers happy paths, edge cases (ghost users, injection attacks), and failure modes.

To run the tests:

```bash
python3 -m pytest
```

## Building from Source (Binary)

You can compile LogGuarder into a standalone Linux executable that requires no Python installation.

1. **Build the binary:**
```bash
pyinstaller logguard.spec
```


2. **Run the executable:**
```bash
./dist/logguard samples/test_auth.log
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

I chose the **Rich** library over standard `print()` statements. Color-coded alerts and structured tables allow operators to spot critical threats instantly, reducing "alert fatigue."

### 5. Compiled Binary Distribution
To adhere to the **Write Once, Run Anywhere** philosophy, the project includes a PyInstaller build, resulting binary bundles the Python interpreter and the Rich dependency.

## Project Structure

```text
log_guarder/
├── samples/           # Test data
├── tests/             # Pytest suite
├── parser/
│   ├── engine.py      # Core parsing logic
│   └── models.py      # Data structures
├── dist/              # Compiled binary (after build)
├── main.py            # Entry point & CLI
├── logguard.spec      # PyInstaller build config
├── requirements.txt   # Dependencies
└── README.md          # Documentation
```
