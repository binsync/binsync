import sys

from binsync.common.ui.qt_objects import (
    QEvent,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QDialog,
    QMenu,
    QPushButton,
    QMainWindow,
    QApplication
)
from binsync import StackVariable, StackOffsetType
import random



def generate_random_stack_var(offset):
    default_addr = 0xdeadbeef
    default_off_type = StackOffsetType.ANGR

    type_choices = {
        "bool": 1,
        "char": 1,
        "int": 4,
        "long": 8,
        "int *": 8,
        "char *": 8,
        "long *": 8
    }
    _type, _size = random.choice(list(type_choices.items()))
    _name = f"v{random.randint(1,90)}"

    return StackVariable(offset, default_off_type, _name, _type, _size, default_addr)


def generate_random_vars():
    max_offsets = random.choice([0x30, 0x40, 0x50])
    stack_vars = {}
    for off in range(0, max_offsets, 8):
        stack_vars[off] = (generate_random_stack_var(off), generate_random_stack_var(off))

    return stack_vars



class MergeWin(QDialog):
    def __init__(self, stack_vars):
        super().__init__()

        self.setWindowTitle("Manual Merge")

        self.stack_vars = stack_vars


        QBtn1 = QDialogButtonBox.Ok

        self.buttonBox = QDialogButtonBox(QBtn1)
        self.buttonBox.accepted.connect(self.okay_button)


        self.layout = QGridLayout()
        self.setLayout(self.layout)


        x = len(self.stack_vars)  #sets the number of lines added to the window


        self.final = {}
        self.names = {}
        self.types = {}

        self.org_pairs = []

        for i, k in enumerate(self.stack_vars.keys()):

            result = self.stack_vars[k]
            self.sv1: StackVariable = result[0]
            self.sv2: StackVariable = result[1]

            # type
            type_ = QLabel(self.sv1.type)
            self.layout.addWidget(type_, i, 1)
            type_.installEventFilter(self)

            # name
            name_ = QLabel(self.sv1.name)
            self.layout.addWidget(name_, i, 2)
            name_.installEventFilter(self)

            # adds the new type_ and name_ value to the types and names dicts
            self.types[type_] = self.sv1.type, self.sv2.type, k
            self.names[name_] = self.sv1.name, self.sv2.name, k

            # checks for a conflict; if there is, the text will be red.
            if self.sv1.type != self.sv2.type:
                type_.setStyleSheet("color: red")

            if self.sv1.name != self.sv2.name:
                type_.setStyleSheet("color: red")


            # creates a final dictionary that has all the StackVariables (type, name) recorded; dict is updated after user makes changes
            self.final[self.sv1.stack_offset] = self.sv1.copy()

            # values added to org_pairs list to be checked in tuple_pairs
            self.org_pairs.append((type_, name_))


        self.layout.addWidget(self.buttonBox, x+2, 3)

    def tuple_pairs(self, source):
        tuples_ = self.org_pairs
        for tup in tuples_:
            if source == tup[0]:
                other = tup[1]
                break
            elif source == tup[1]:
                other = tup[0]
                break
        return other



    def eventFilter(self, source, event):
        if event.type() == QEvent.ContextMenu and source in self.types:

            menu = QMenu()
            for i in range(2):
                menu.addAction(self.types[source][i])

            action = menu.exec_(event.globalPos())

            if action:
                # if there is a conflict and the user makes a change, the text will turn purple
                if self.types[source][1] != self.types[source][2]:
                    source.setStyleSheet("color: purple")

                # the option the user chooses, replaces the text in the window
                item = action.text()
                source.setText(f"{item} ")
                other = self.tuple_pairs(source)
                self.set_type = item

                # the dictionary is updated with the new pair.
                k = self.types[source][2]
                self.final[k].type = item


        if event.type() == QEvent.ContextMenu and source in self.names:
            menu = QMenu()
            for i in range(2):
                menu.addAction(self.names[source][i])

            action = menu.exec_(event.globalPos())

            if action:
                # if there is a conflict and the user makes a change, the text will turn purple
                if self.names[source][1] != self.names[source][2]:
                    source.setStyleSheet("color: purple")

                # the option the user chooses, replaces the text in the window
                item = action.text()
                source.setText(f"{item}")
                other = self.tuple_pairs(source)
                self.set_type = item

                # the dictionary is updated with the new pair.
                k = self.names[source][2]
                self.final[k].name = item


        return super().eventFilter(source, event)


    def okay_button(self):
        self.close()
        print("the user pressed the 'okay' button \n")
        print("Final Dictionary:")
        print(self.final)
