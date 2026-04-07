#!/usr/bin/env python3
"""
facedancer-hid-fuzz.py
Description : USB HID descriptor fuzzer using Facedancer (via Cynthion
              or GreatFET). Enumerates malformed HID report descriptors
              to discover host driver parsing bugs. Each test case sends
              a different descriptor mutation and monitors for OS errors.
Requires    : facedancer (pip install facedancer), Cynthion or GreatFET One
Usage       : python3 facedancer-hid-fuzz.py [test_count]
"""

import sys
import time
import random
import os
from datetime import datetime

try:
    from facedancer import FacedancerUSBApp
    from facedancer.devices.keyboard import USBKeyboardDevice
    from facedancer.USBConfiguration import USBConfiguration
    from facedancer.USBInterface import USBInterface
except ImportError:
    print("[!] facedancer not found. Install with: pip install facedancer")
    print("    See: https://github.com/greatscottgadgets/facedancer")
    sys.exit(1)

TEST_COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 50
LOOT_DIR = f"./loot/hid-fuzz-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, "fuzz_results.log")

# Valid HID keyboard descriptor baseline
BASE_DESCRIPTOR = bytes([
    0x05, 0x01,  # Usage Page (Generic Desktop)
    0x09, 0x06,  # Usage (Keyboard)
    0xA1, 0x01,  # Collection (Application)
    0x05, 0x07,  # Usage Page (Key Codes)
    0x19, 0xE0,  # Usage Minimum (224)
    0x29, 0xE7,  # Usage Maximum (231)
    0x15, 0x00,  # Logical Minimum (0)
    0x25, 0x01,  # Logical Maximum (1)
    0x75, 0x01,  # Report Size (1)
    0x95, 0x08,  # Report Count (8)
    0x81, 0x02,  # Input (Data, Variable, Absolute)
    0x95, 0x01,  # Report Count (1)
    0x75, 0x08,  # Report Size (8)
    0x81, 0x03,  # Input (Constant)
    0x95, 0x05,  # Report Count (5)
    0x75, 0x01,  # Report Size (1)
    0x05, 0x08,  # Usage Page (LEDs)
    0x19, 0x01,  # Usage Minimum (1)
    0x29, 0x05,  # Usage Maximum (5)
    0x91, 0x02,  # Output (Data, Variable, Absolute)
    0x95, 0x01,  # Report Count (1)
    0x75, 0x03,  # Report Size (3)
    0x91, 0x03,  # Output (Constant)
    0x95, 0x06,  # Report Count (6)
    0x75, 0x08,  # Report Size (8)
    0x15, 0x00,  # Logical Minimum (0)
    0x25, 0x65,  # Logical Maximum (101)
    0x05, 0x07,  # Usage Page (Key Codes)
    0x19, 0x00,  # Usage Minimum (0)
    0x29, 0x65,  # Usage Maximum (101)
    0x81, 0x00,  # Input (Data, Array)
    0xC0,        # End Collection
])


def mutate_descriptor(desc):
    """Generate a random mutation of the HID descriptor."""
    d = bytearray(desc)
    mutation = random.choice(['flip_bit', 'insert_byte', 'delete_byte', 'overflow_length', 'corrupt_tag'])

    if mutation == 'flip_bit' and d:
        idx = random.randint(0, len(d) - 1)
        d[idx] ^= (1 << random.randint(0, 7))
    elif mutation == 'insert_byte':
        idx = random.randint(0, len(d))
        d.insert(idx, random.randint(0, 255))
    elif mutation == 'delete_byte' and len(d) > 5:
        idx = random.randint(0, len(d) - 1)
        del d[idx]
    elif mutation == 'overflow_length' and len(d) > 2:
        idx = random.randint(0, len(d) - 2)
        d[idx + 1] = 0xFF  # Set length to max
    elif mutation == 'corrupt_tag':
        idx = random.randint(0, len(d) - 1)
        d[idx] = random.randint(0xF0, 0xFF)

    return bytes(d)


print(f" ==================================================")
print(f"  Facedancer — USB HID Descriptor Fuzzer")
print(f"  Test cases: {TEST_COUNT}")
print(f"  Log: {LOG_FILE}")
print(f" ==================================================")
print("[!] Connect Facedancer to fuzz target, press Enter to start...")
input()

passed = 0
failed = 0

with open(LOG_FILE, 'w') as log:
    log.write("TestCase,MutationLen,Status,Notes\n")

    for i in range(TEST_COUNT):
        mutated = mutate_descriptor(BASE_DESCRIPTOR)
        print(f"[*] Test {i+1}/{TEST_COUNT}: descriptor={len(mutated)}B ", end='', flush=True)

        try:
            app = FacedancerUSBApp(verbose=0)
            dev = USBKeyboardDevice(app)
            # Inject mutated descriptor
            dev.descriptors[3] = mutated  # HID report descriptor
            app.connect(dev)
            time.sleep(0.5)
            app.disconnect()
            passed += 1
            print("OK")
            log.write(f"{i+1},{len(mutated)},PASS,\n")
        except Exception as e:
            failed += 1
            print(f"CRASH: {e}")
            log.write(f"{i+1},{len(mutated)},CRASH,{str(e)[:100]}\n")
            # Save crash descriptor
            crash_file = os.path.join(LOOT_DIR, f"crash_{i+1}.bin")
            with open(crash_file, 'wb') as cf:
                cf.write(mutated)
        time.sleep(0.2)

print(f"\n[+] Fuzzing complete: {passed} passed, {failed} crashes")
print(f"[+] Log: {LOG_FILE}")
if failed > 0:
    print(f"[!] Crash descriptors saved to: {LOOT_DIR}/crash_*.bin")
