import os
import time

print("=" * 60)
print("CONTROLLED CRITICAL SECURITY TEST PROCESS")
print("=" * 60)
print(f"PID: {os.getpid()}")
print("This process is intentionally created for EndpointGuard testing.")
print("Expected behavior: Agent should detect and terminate this process.")
print("=" * 60)

while True:
    # Simulated sustained abnormal workload
    value = 0

    for i in range(2_000_000):
        value += i * i

    time.sleep(0.01)