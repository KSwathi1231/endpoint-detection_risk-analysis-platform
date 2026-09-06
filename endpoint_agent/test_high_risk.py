import time
import os

print("Controlled High Risk Test Process Started")
print(f"PID: {os.getpid()}")
print("Simulating sustained abnormal resource usage...")

while True:
    # Controlled CPU-intensive behavior for EDR testing
    result = 0

    for i in range(1_000_000):
        result += i * i

    time.sleep(0.01)