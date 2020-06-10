from src import compile
import os
import yara


def test_get_multiple_rules_files(mocker):
    mocker.patch("os.walk")
    os.walk.return_value = [("", "", ["one.yar", "two.yara"])]
    files = compile.get_rules_files()
    assert len(list(files)) == 2


def test_get_no_rules_files(mocker):
    mocker.patch("os.walk")
    os.walk.return_value = []
    files = compile.get_rules_files()
    assert len(list(files)) == 0


def test_valid_file_compiles(mocker):
    mocker.patch("yara.compile")
    res = compile.can_file_compile("path")
    assert res
    yara.compile.reset_mock()


def test_invalid_file_compiles(mocker):
    mocker.patch("yara.compile")
    yara.compile.side_effect = yara.SyntaxError()
    res = compile.can_file_compile("path")
    assert not res
    yara.compile.reset_mock()


def test_create_file(mocker):
    mocker.patch("os.walk")
    os.walk.return_value = [("", "", ["one.yar", "two.yara"])]
    mocker.patch("yara.compile")
    compile.create_output()
    yara.compile.assert_called_with(filepaths={'one.yar': './one.yar', 'two.yara': './two.yara'},
                                    externals={'extension': '', 'filename': '', 'filepath': '', 'filetype': ''})
