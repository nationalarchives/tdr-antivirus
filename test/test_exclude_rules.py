from src.exclude_rules import exclude_rules
import plyara
import shutil
import os


def test_exclude_rules():
    parser = plyara.Plyara()
    shutil.copy("test/testrules/test.yar", "test.yar")
    exclude_rules("test/testrules.json")
    with open("test.yar", 'r') as test_yar_file:
        parsed = parser.parse_string(test_yar_file.read())
    assert len(parsed) == 1
    assert parsed[0]["rule_name"] == "IncludedRule"
    os.remove("test.yar")
