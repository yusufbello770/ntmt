# Detection thresholds
BANDWIDTH_THRESHOLD = 10 * 1024 * 1024  # 10 MB/min
PORT_SCAN_THRESHOLD = 15                 # 15 SYN packets
REQUEST_RATE_THRESHOLD = 100             # 100 requests/sec
SQL_INJECTION_REGEX = r"('|--|; DROP|1=1|UNION SELECT)"