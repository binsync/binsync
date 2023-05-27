ui_version = "PySide6"


def set_ui_version(version):
    global ui_version
    valid_version = [
        "PyQt5",
        "PySide2",
        "PySide6"
    ]

    if version in valid_version:
        ui_version = version
    else:
        raise Exception("Failed to set BinSync UI version")
