import yara
import os
import logging

import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

rules = yara.load("/rules/output")
rules_old = yara.load("/rules/output-old")

match_len = 0
rules_old_id = sorted([ro.identifier for ro in rules_old])
rules_id = sorted([r.identifier for r in rules])

if rules_old_id != rules_id:
    changed_rules = [item for item in rules_old_id if item not in rules_id]
    logging.debug(f"Rules have changed. The following rules are different {changed_rules}")
    for file in os.listdir("/testfiles"):
        matches = rules.match(f"/testfiles/{file}")
        av_message = "No match found" if len(matches) == 0 else " ".join([m.rule for m in matches])
        logging.debug(f"{file} {av_message}")
        match_len = match_len + len(matches)

    if match_len > 0:
        sys.exit(1)
else:
    sys.exit(3)
