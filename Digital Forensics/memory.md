### Types of Data Found in RAM for Incident Investigation:

- Network connections
- File handles and open files
- Open registry keys
- Running processes on the system
- Loaded modules
- Loaded device drivers
- Command history and console sessions
- Kernel data structures
- User and credential information
- Malware artifacts
- System configuration
- Process memory regions



## Incident Investigation Process

### Process Identification and Verification:
- Enumerate all running processes.
- Determine their origin within the operating system.
- Cross-reference with known legitimate processes.
- Highlight any discrepancies or suspicious naming conventions.

### Deep Dive into Process Components:
- Examine DLLs linked to the suspicious process.
- Check for unauthorized or malicious DLLs.
- Investigate any signs of DLL injection or hijacking.

### Network Activity Analysis:
- Review active and passive network connections in the system's memory.
- Identify and document external IP addresses and associated domains.
- Determine the nature and purpose of the communication.
  - Validate the process' legitimacy.
  - Assess if the process typically requires network communication.
  - Trace back to the parent process.
  - Evaluate its behavior and necessity.

### Code Injection Detection:
- Use memory analysis tools to detect anomalies or signs of these techniques.
- Identify any processes that seem to occupy unusual memory spaces or exhibit unexpected behaviors.

### Rootkit Discovery:
- Scan for signs of rootkit activity or deep OS alterations.
- Identify any processes or drivers operating at unusually high privileges or exhibiting stealth behaviors.

### Extraction of Suspicious Elements:
- Dump the suspicious components from memory.
- Store them securely for subsequent examination using specialized forensic tools.


## The Volatility Framework

- `pslist`: Lists the running processes.
- `cmdline`: Displays process command-line arguments.
- `netscan`: Scans for network connections and open ports.
- `malfind`: Scans for potentially malicious code injected into processes.
- `handles`: Scans for open handles.
- `svcscan`: Lists Windows services.
- `dlllist`: Lists loaded DLLs (Dynamic-link Libraries) in a process.
- `hivelist`: Lists the registry hives in memory.

  
