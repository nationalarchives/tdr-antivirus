import yara
import os

import sys
rules = yara.load("/rules/output")
rules_old = yara.load("/rules/output-old")

match_len = 0
if sorted([ro.identifier for ro in rules_old]) != sorted([r.identifier for r in rules]):
    for file in os.listdir("/testfiles"):
        matches = rules.match(f"/testfiles/{file}")
        av_message = "No match found" if len(matches) == 0 else " ".join([m.rule for m in matches])
        print(f"{file} {av_message}")
        match_len = match_len + len(matches)

    if match_len > 0:
        sys.exit(1)
else:
    sys.exit(3)
