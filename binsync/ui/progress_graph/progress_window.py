import logging
import typing
import os

import networkx as nx
import numpy as np

from libbs.ui.qt_objects import (
    # QtWidgets
    QGraphicsScene,
    QGraphicsView,
    QGraphicsEllipseItem,
    QGraphicsTextItem,
    QGraphicsLineItem,
    QGraphicsItem,
    QLabel,
    QLineEdit,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QDialog,
    QPushButton,
    QCheckBox,
    QFileDialog,
    # QtGui
    QPen, QBrush, QColor, QPainter, QFont, QFontMetrics,
    # QtCore
    Qt, QLineF
)
from libbs.artifacts import Function
from binsync.extras import EXTRAS_AVAILABLE

from .summarize import summarize_changes

if typing.TYPE_CHECKING:
    from binsync.controller import BSController

_l = logging.getLogger(__name__)

try:
    from networkx.drawing.nx_agraph import graphviz_layout
    HAS_PYGRAPHVIZ = True
except Exception:
    HAS_PYGRAPHVIZ = False
    _l.warning("pygraphviz not installed, progress view may be ugly.")


class NodeItem(QGraphicsEllipseItem):
    """
    A node that:
      - Color depends on 'hotness'
      - Autosizes to fit its text at 'size=1' minimum
      - Then scales that size by the node's 'size' attribute in [1..10]
      - Only one node at a time can have a bold black outline
      - Clicking the node pans the view to center on it (camera movement)
      - Double-click prints "Node {label}" to the terminal
    """
    currently_selected_node = None

    def __init__(
        self,
        func: Function,
        x,
        y,
        hotness=0.0,
        size=1,  # size in [1..10]
        parent=None,
        view=None,
        controller=None,
    ):
        self._func = func
        self._controller = controller
        label_text = func.name

        # Step 1: measure text to find the base diameter for size=1
        font = QFont("Arial", 10)
        fm = QFontMetrics(font)
        text_width = fm.horizontalAdvance(label_text)
        text_height = fm.height()
        base_diameter = 32

        # Step 2: scale the diameter by 'size'
        diameter = base_diameter * size

        super().__init__(-diameter / 2, -diameter / 2, diameter, diameter, parent)
        self.radius = diameter / 2
        self.view = view
        self._edges = []
        self.setPos(x, y)

        # Pen styles
        self.default_pen = QPen(Qt.black, 2)
        self.highlight_pen = QPen(Qt.black, 5)
        self.setPen(self.default_pen)

        # Fill color
        fill_color = self.color_from_hotness(hotness)
        self.setBrush(QBrush(fill_color))

        # Create text item outside the node
        self.text_item = QGraphicsTextItem(label_text, self.scene())
        self.text_item.setFont(font)
        self.text_item.setDefaultTextColor(Qt.white)
        text_bounds = self.text_item.boundingRect()

        # Position the text above the node
        text_x = self.x() - text_bounds.width() / 2
        text_y = self.y() - self.radius - text_bounds.height() - 5  # Offset above the node

        self.text_item.setPos(text_x, text_y)

        # Movable, selectable
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )

    def add_edge(self, edge):
        self._edges.append(edge)

    def itemChange(self, change, value):
        # Update edges and reposition label if the node moves
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.update_positions()
            # Update text position
            text_bounds = self.text_item.boundingRect()
            self.text_item.setPos(
                self.x() - text_bounds.width() / 2,
                self.y() - self.radius - text_bounds.height() - 5
            )
        return super().itemChange(change, value)

    def mouseDoubleClickEvent(self, event):
        # Bold black outline for only one selected node
        prev = NodeItem.currently_selected_node
        # TODO: this is a stopgap fix for Windows. A permission error can occur because the main and new child process access the same repo.
        if prev is not None and prev is not self:
            _l.debug("Windows temp permissions error")
            if prev.scene() is not None:
                prev.setPen(prev.default_pen)

        self.setPen(self.highlight_pen)
        NodeItem.currently_selected_node = self

        self._controller.deci.gui_goto(self._func.addr)
        super().mouseDoubleClickEvent(event)

    @staticmethod
    def color_from_hotness(hotness: float) -> QColor:
        """
        If hotness <= 0.0, node is white (255,255,255).
        Otherwise, map [0..1] from light pink -> red.
        """
        if hotness <= 0.0:
            return QColor(255, 255, 255)  # white
        h = min(1.0, hotness)
        r = 255
        g = int(200 * (1 - h))
        b = int(200 * (1 - h))
        return QColor(r, g, b)


class EdgeItem(QGraphicsLineItem):
    """
    Connects two NodeItems. Lines stop at the node boundaries, not at centers.
    """
    def __init__(self, node1, node2, indirect=False):
        super().__init__()
        self.node1 = node1
        self.node2 = node2
        self.indirect = indirect

        pen = QPen(Qt.black, 2)
        if self.indirect:
            pen.setStyle(Qt.DashLine)
        self.setPen(pen)

        self.update_positions()

    def update_positions(self):
        line = QLineF(self.node1.scenePos(), self.node2.scenePos())
        uv = line.unitVector()

        # Shift start by node1's radius
        p1 = line.p1()
        p1.setX(p1.x() + uv.dx() * self.node1.radius)
        p1.setY(p1.y() + uv.dy() * self.node1.radius)

        # Shift end by node2's radius
        p2 = line.p2()
        p2.setX(p2.x() - uv.dx() * self.node2.radius)
        p2.setY(p2.y() - uv.dy() * self.node2.radius)

        self.setLine(QLineF(p1, p2))


class GraphView(QGraphicsView):
    """
    Allows panning (drag) and zooming (mouse wheel).
    """
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(QPainter.Antialiasing)

    def wheelEvent(self, event):
        zoom_factor = 1.15
        if event.angleDelta().y() > 0:
            self.scale(zoom_factor, zoom_factor)
        else:
            self.scale(1 / zoom_factor, 1 / zoom_factor)


class ProgressGraphWidget(QDialog):
    """
    A QWidget that displays a NetworkX graph.
    """
    def __init__(self, graph: nx.DiGraph = None, controller: "BSController" = None, tag=None, parent=None):
        super().__init__(parent)
        self._graph = graph
        self._completion = 0
        self._controller = controller
        self._git_client = controller.client.copy(copy_files=True)
        self._tags = [""] + [tag.name for tag in self._git_client.repo.tags]
        self._tag_selection = tag or ""

        self._show_only_changed = False
        self._layouts = ["dot", "fdp", "neato", "twopi", "circo", "sfdp"]

        self.displayed_graph = None
        self._graph_view = None
        _l.info("ProgressGraphWidget created with tag %s", self._tag_selection)

        self._init_widgets()

    def _update_progress_widgets(self):
        # rebuild the graph
        self.displayed_graph = self._analyze_graph()

        # first, update the completion label with the correct label
        self.completion_label.setText(f"Completion: <span style='color: green;'>{self._completion}%</span>")
        # no need to update hotness, it is static for now...

        if self._graph_view is not None:
            # Remove and delete the old view to fully destroy C++ items
            old_view = self._graph_view
            self.main_layout.removeWidget(old_view)
            try:
                if old_view.scene() is not None:
                    old_view.scene().clear()
            except Exception:
                pass
            old_view.deleteLater()
            self._graph_view = None

        # update the actual graph view
        self._build_graph_view()
        self.main_layout.addWidget(self._graph_view)

    def _build_graph_view(self):
        # Create scene
        scene = QGraphicsScene(self)
        scene.setBackgroundBrush(QBrush(QColor("#333333")))
        # Reset any stale selection from a previous scene
        NodeItem.currently_selected_node = None

        # If no graph was provided, create a small sample
        # Each node has 'hotness' in [0..1], and 'size' in [1..10] (default=5).
        if self.displayed_graph is None:
            self._controller.deci.error("No graph provided to ProgressGraphWidget")
            return

        # Layout: graphviz "dot" if possible, else spring
        if HAS_PYGRAPHVIZ:
            pos = graphviz_layout(self.displayed_graph, prog=self._layouts[0])
        else:
            pos = nx.spring_layout(self.displayed_graph)

        # Create a QGraphicsView
        self._graph_view = GraphView(scene, self)

        # Build node items
        node_items = {}
        for func_node, data in self.displayed_graph.nodes(data=True):
            hotness = data.get("hotness", 0.0)
            size_val = data.get("size", 5)
            x, y = pos[func_node]
            item = NodeItem(
                func_node,
                x=x,
                y=y,
                hotness=hotness,
                size=size_val,  # <--- scaled node
                view=self._graph_view,
                controller=self._controller
            )
            scene.addItem(item)
            scene.addItem(item.text_item)
            node_items[func_node] = item

        # Build edges
        for u, v, edata in self.displayed_graph.edges(data=True):
            indirect = edata.get("indirect", False)
            edge_item = EdgeItem(node_items[u], node_items[v], indirect)
            scene.addItem(edge_item)
            node_items[u].add_edge(edge_item)
            node_items[v].add_edge(edge_item)

    def _init_widgets(self):
        # start adding things
        self.setWindowTitle("Graph Viewer")

        self.main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()

        # make a widget for all the left items
        left_widget = QWidget()
        left_layout = QHBoxLayout(left_widget)
        left_layout.setSpacing(15)

        # make a widget for all the right items
        right_widget = QWidget()
        right_layout = QHBoxLayout(right_widget)
        right_layout.setSpacing(15)

        # Label left (only `change%` is green)
        self.completion_label = QLabel(f"Completion: <span style='color: green;'>Loading...</span>")
        self.completion_label.setStyleSheet("font-size: 16px;")
        left_layout.addWidget(self.completion_label)

        # Label left, tag selection
        self.tag_label = QLabel("Tag: ")
        self.tag_label.setStyleSheet("font-size: 16px;")
        self.tag_dropdown = QComboBox()
        self.tag_dropdown.addItems(self._tags)
        self.tag_dropdown.currentTextChanged.connect(self.on_tag_selected)
        # Create a container widget to hold label and dropdown
        tag_widget = QWidget()
        tag_layout = QHBoxLayout(tag_widget)
        tag_layout.addWidget(self.tag_label)
        tag_layout.addWidget(self.tag_dropdown)
        tag_layout.setSpacing(1)  # Adjust spacing between label and dropdown
        tag_layout.setContentsMargins(0, 0, 0, 0)  # Remove extra margins
        tag_widget.setLayout(tag_layout)
        left_layout.addWidget(tag_widget)

        # Label left, graph layout selection
        self.layout_label = QLabel("Layout: ")
        self.layout_label.setStyleSheet("font-size: 16px;")
        self.layout_dropdown = QComboBox()
        self.layout_dropdown.addItems(["dot", "fdp", "neato", "twopi", "circo", "sfdp"])
        self.layout_dropdown.currentTextChanged.connect(self._graph_layout_changed)
        # Create a container widget to hold label and dropdown
        layout_widget = QWidget()
        layout_layout = QHBoxLayout(layout_widget)
        layout_layout.addWidget(self.layout_label)
        layout_layout.addWidget(self.layout_dropdown)
        layout_layout.setSpacing(1)  # Adjust spacing between label and dropdown
        layout_layout.setContentsMargins(0, 0, 0, 0)  # Remove extra margins
        layout_widget.setLayout(layout_layout)
        left_layout.addWidget(layout_widget)

        # Only changed checkbox
        self.only_changed_checkbox = QCheckBox("Only Changed")
        self.only_changed_checkbox.stateChanged.connect(self._only_changed_clicked)
        right_layout.addWidget(self.only_changed_checkbox)

        # Summarize button
        self.summarize_button = QPushButton("Summarize")
        self.summarize_button.clicked.connect(self.summarize)
        right_layout.addWidget(self.summarize_button)

        # Label right (only `changes` is pink)
        self.hotness_label = QLabel("Hotness: <span style='color: pink;'>changes</span>")
        self.hotness_label.setStyleSheet("font-size: 16px;")
        right_layout.addWidget(self.hotness_label)

        # refresh button
        #self.refresh_button = QPushButton("Refresh")
        #self.refresh_button.clicked.connect(self._print_refresh)
        #left_layout.addWidget(self.refresh_button)

        top_layout.addWidget(left_widget, alignment=Qt.AlignLeft)
        top_layout.addWidget(right_widget, alignment=Qt.AlignRight)
        self.main_layout.addLayout(top_layout)

        # adds the graph view
        self._update_progress_widgets()

        self.setLayout(self.main_layout)
        self.setStyleSheet("background-color: #222222;")
        self.resize(1000, 800)

    def _analyze_graph(self, max_changes_heat=10) -> nx.DiGraph:
        # check if there is a valid selected tag
        commit_hash = None
        if self._tag_selection:
            tag_ref = self._git_client.repo.tag(self._tag_selection)
            try:
                commit_hash = tag_ref.commit.hexsha
            except Exception as e:
                _l.error("Failed to get commit hash for tag %s: %s", self._tag_selection, e)

        # collect function changes
        func_changes_by_users = self._controller.compute_changes_per_function(
            exclude_master=True, client=self._git_client, commit_hash=commit_hash
        )
        func_changes = {}
        for func_addr, user_changes in func_changes_by_users.items():
            func_changes[func_addr] = sum(user_changes.values())
            #_l.info(f"Function {hex(func_addr)} has {func_changes[func_addr]} changes")

        func_heats = {}
        total_completed_funcs = 0
        # changed_funcs = set(func_addr for func_addr, changes in func_changes.items() if changes > 0)
        for func_addr, changes in func_changes.items():
            if changes > 0:
                func_heats[func_addr] = min(changes, max_changes_heat) / max_changes_heat
                total_completed_funcs += 1
        complete_percent = int((total_completed_funcs / len(func_changes)) * 100)
        self._completion = complete_percent

        # find the changed function nodes in the graph
        changed_func_nodes = set()
        for node in self._graph.nodes:
            if node.addr in func_heats:
                changed_func_nodes.add(node)

        func_nodes_in_graph = changed_func_nodes.copy()
        # find every node that is connected, dist of 1, from changed funcs
        if not self._show_only_changed:
            for node in changed_func_nodes:
                for neighbor in self._graph.successors(node):
                    func_nodes_in_graph.add(neighbor)
                for neighbor in self._graph.predecessors(node):
                    func_nodes_in_graph.add(neighbor)

        # TODO: do indirect edges
        # make a subgraph of the graph with only the changed functions
        analyzed_graph = nx.DiGraph(self._graph.subgraph(func_nodes_in_graph))

        node_sizes = []
        for node in analyzed_graph.nodes:
            node_sizes.append(node.size)
        size_variances = self.compute_size_outlier_scores(node_sizes)

        # set heat & size attributes on the nodes
        for node in analyzed_graph.nodes:
            node_data = analyzed_graph.nodes[node]
            node_data["hotness"] = func_heats.get(node.addr, 0)
            node_data["size"] = size_variances[node.size]

        return analyzed_graph

    #
    # Callbacks
    #

    def _only_changed_clicked(self, state):
        show_only_changed = state == Qt.Checked
        self._show_only_changed = show_only_changed
        self._update_progress_widgets()

    def _graph_layout_changed(self, layout):
        self._layouts.remove(layout)
        self._layouts.insert(0, layout)
        self._update_progress_widgets()

    def on_tag_selected(self, tag, *args, **kwargs):
        _l.info("Selected tag: %s", tag)
        self._tag_selection = tag
        self._update_progress_widgets()

    
    def checkApi(self):
        if "sk" in os.environ.get("OPENAI_API_KEY"): #Check if the api key is set
            _l.info("API Key set already, good to go!")
        else:
            dialog = QDialog(self) 
            dialog.setWindowTitle("Enter Key")
            
            
            dlg_layout = QVBoxLayout()
            
            key_input = QLineEdit()
            key_input.setPlaceholderText("Enter OpenAi API Key:")
            
            save_btn = QPushButton("Save")
            
            dlg_layout.addWidget(QLabel("Key:"))
            dlg_layout.addWidget(key_input)
            def setAPIKey():
                user_key = key_input.text()
                os.environ["OPENAI_API_KEY"] = user_key #Will be set so that a dialog opens for user to enter key
                dialog.accept()
            dlg_layout.addWidget(save_btn)
            
            dialog.setLayout(dlg_layout)
            save_btn.clicked.connect(setAPIKey)

            
            dialog.exec()

    def summarize(self, *args, **kwargs):
        if not EXTRAS_AVAILABLE:
            _l.error("Summarization requires extras, which are not available.")
            return

        #Call checkApi here, so we can check for extras first and then see if api key is set before selecting a save file
        self.checkApi()

        file_location, _ = QFileDialog.getSaveFileName(None, "Save File", "", "All Files (*);;Text Files (*.txt)")
        _l.info("Summarizing changes...")
        summarize_changes(self._controller, self.displayed_graph, file_location)

    @staticmethod
    def compute_size_outlier_scores(node_sizes: list[int], max_size=3, min_size=1) -> dict:
        """
        Compute the outlier scores for the sizes of the nodes in the graph.
        """
        variances = {}
        mean = np.mean(node_sizes)
        std = np.std(node_sizes)

        if std == 0:
            return {n: 0.5 * max_size for n in node_sizes}

        for size in node_sizes:
            # Compute Z-score
            z_score = abs(size - mean) / std

            # Apply a sigmoid function to map to (0,1), with strong suppression of outliers
            score = np.exp(-z_score)  # Exponentially decay based on distance
            variances[size] = max(int((1 - score) * max_size), min_size)

        return variances

    def closeEvent(self, event):
        self._controller.progress_view_open = False
        NodeItem.currently_selected_node = None