#! /usr/bin/python3
import json
import plyara
from plyara.utils import rebuild_yara_rule

parser = plyara.Plyara()


def exclude_rules(rules_file_name):
    with open(rules_file_name, "r") as rules_json_file:
        rules_json = json.loads(rules_json_file.read())
        for repository in rules_json["repositories"]:
            excluded_rules = repository["excludeRules"]
            for file_name in excluded_rules.keys():
                rule_names = excluded_rules[file_name]
                with open(file_name, 'r') as file:
                    yara_rules = parser.parse_string(file.read())
                    filtered_rules = [rule for rule in yara_rules if rule['rule_name'] not in rule_names]
                parser.clear()

                with open(file_name, 'w') as file:
                    for rule in filtered_rules:
                        file.write(rebuild_yara_rule(rule))


if __name__ == "__main__":
    exclude_rules("/rules/rules.json")
