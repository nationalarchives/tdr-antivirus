import yara
import os

import sys
rules = yara.load("/rules/output")
match_len = 0
for file in os.listdir("/testfiles"):
    matches = rules.match(f"/testfiles/{file}")
    av_message = "No match found" if len(matches) == 0 else " ".join([m.rule for m in matches])
    print(f"{file} {av_message}")
    match_len = match_len + len(matches)

if match_len > 0:
    sys.exit(1)
