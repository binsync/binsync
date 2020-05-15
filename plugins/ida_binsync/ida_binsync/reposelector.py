from __future__ import absolute_import, division, print_function

import json
import os

import idaapi
from idaapi import Form

from ida_binsync import UI_DIR
from PyQt5 import uic
from PyQt5.QtCore import Qt
from PyQt5.Qt import qApp
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QDialog, QFileSystemModel


class RepoSelector(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """

    def __init__(self):
        self.invert = False
        Form.__init__(
            self,
            r"""STARTITEM {id:iStr1}
BUTTON YES NONE
BUTTON CANCEL NONE
Select A Repo
{FormChangeCb}
<#Hint1#User name:  {iStr1}>
<#Select Repo#Select Repo:{iDir}>
<Create New Repo:{rNormal}>{cGroup1}>
<##Connect:{iButton1}> <##Cancel:{iButton2}>
""",
            {
                "iStr1": Form.StringInput(swidth=40),
                "iDir": Form.DirInput(swidth=40),
                "cGroup1": Form.ChkGroupControl(("rNormal",)),
                "iButton1": Form.ButtonInput(self.OnButton1),
                "iButton2": Form.ButtonInput(self.OnButton2),
                "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
            },
        )

    def OnButton1(self, code=0):
        self.user_name = self.GetControlValue(self.iStr1)
        self.repo_dir = self.GetControlValue(self.iDir)
        self.init_repo = True if self.GetControlValue(self.cGroup1) == 1 else False

        if not self.user_name:
            self.display_error("Invalid user name\nUser name cannot be empty.")
        elif not os.path.isdir(self.repo_dir):
            self.display_error(
                "Repo does not exist\nThe specified sync repo does not exist."
            )
        else:
            self.Close(1)

    def display_error(self, error_message):
        idaapi.warning(error_message)

    def OnButton2(self, code=0):
        self.Close(0)

    def OnFormChange(self, fid):
        return 1


class RepoError(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """

    def __init__(self, err_message):
        self.invert = False
        Form.__init__(
            self,
            r"""STARTITEM {id:error_message}
BUTTON YES OK
BUTTON CANCEL NONE
Error
{FormChangeCb}
{error_message}
""",
            {
                "error_message": Form.StringLabel(err_message),
                "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
            },
        )

    def OnFormChange(self, fid):
        return 1

class UserSelector(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """

    def __init__(self, user_list=[]):
        self.invert = False
        print("USERS")
        self.user_list = user_list
        Form.__init__(
            self,
            r"""STARTITEM {id:cbReadonly}
BUTTON YES NONE
BUTTON CANCEL NONE
Select A User
{FormChangeCb}
<Dropdown list (readonly):{cbReadonly}>
<##OK:{iButton1}> <##Cancel:{iButton2}>
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'cbReadonly': Form.DropdownListControl(
                        items=user_list,
                        readonly=True,
                        selval=0,
                        swidth=20),
            "iButton1": Form.ButtonInput(self.OnButton1),
            "iButton2": Form.ButtonInput(self.OnButton2),
        })

    def OnButton1(self, code=0):
        self.selected_user = self.user_list[self.GetControlValue(self.cbReadonly)]
        self.Close(1)

    def OnButton2(self, code=0):
        self.Close(0)

    def OnFormChange(self, fid):
        return 1

