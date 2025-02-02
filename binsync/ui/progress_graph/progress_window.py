import logging
import typing

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
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    # QtGui
    QPen, QBrush, QColor, QPainter, QFont, QFontMetrics,
    # QtCore
    Qt, QLineF
)

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
        label_text,
        x,
        y,
        hotness=0.0,
        size=5,  # size in [1..10]
        parent=None,
        view=None,
        controller=None,
    ):
        self._controller = controller
        # Step 1: measure text to find the base diameter for size=1
        font = QFont("Arial", 10)
        fm = QFontMetrics(font)
        text_width = fm.horizontalAdvance(label_text)
        text_height = fm.height()
        base_diameter = max(text_width + 20, text_height + 20)

        # Step 2: scale the diameter by 'size'
        # If size=1 => diameter=base_diameter (just big enough to fit text)
        # If size=10 => diameter=10x base_diameter
        diameter = base_diameter * size

        super().__init__(-diameter/2, -diameter/2, diameter, diameter, parent)
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

        # Create text item
        self.text_item = QGraphicsTextItem(label_text, self)
        self.text_item.setFont(font)
        self.text_item.setDefaultTextColor(Qt.black)
        text_bounds = self.text_item.boundingRect()
        # Center text
        self.text_item.setPos(-text_bounds.width()/2, -text_bounds.height()/2)

        # Movable, selectable
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )

    def add_edge(self, edge):
        self._edges.append(edge)

    def itemChange(self, change, value):
        # Update edges if the node moves
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.update_positions()
        return super().itemChange(change, value)

    def mouseDoubleClickEvent(self, event):
        label_text = self.text_item.toPlainText()
        print(f"Node {label_text} clicked")
        # Bold black outline for only one selected node
        if NodeItem.currently_selected_node and NodeItem.currently_selected_node is not self:
            NodeItem.currently_selected_node.setPen(NodeItem.currently_selected_node.default_pen)

        self.setPen(self.highlight_pen)
        NodeItem.currently_selected_node = self

        func_addr = label_text.split("_")[1]
        try:
            func_addr = int(func_addr, 16)
        except:
            func_addr = None

        if func_addr is not None:
            normalized_addr = func_addr - 0x400000
            self._controller.deci.gui_goto(normalized_addr)

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


class ProgressGraphWidget(QWidget):
    """
    A QWidget that displays a NetworkX graph.
    """
    def __init__(self, graph: nx.DiGraph = None, completion: int = 0, controller: "BSController" = None, parent=None):
        super().__init__(parent)
        self._graph = graph
        self._completion = completion
        self._controller = controller
        self.analyzed_graph = self._analyze_graph()
        self._refresh_widgets()

    def _refresh_widgets(self):
        self.setWindowTitle("Graph Viewer")

        main_layout = QVBoxLayout(self)
        top_layout = QHBoxLayout()

        # Label left
        self.completion_label = QLabel(f"Completion: {self._completion}%")
        self.completion_label.setStyleSheet("color: green; font-size: 16px;")

        # Label right
        self.hotness_label = QLabel("Hotness: changes")
        self.hotness_label.setStyleSheet("color: red; font-size: 16px;")

        top_layout.addWidget(self.completion_label, alignment=Qt.AlignLeft)
        top_layout.addWidget(self.hotness_label, alignment=Qt.AlignRight)
        main_layout.addLayout(top_layout)

        # Create scene
        scene = QGraphicsScene(self)
        scene.setBackgroundBrush(QBrush(QColor("#333333")))

        # If no graph was provided, create a small sample
        # Each node has 'hotness' in [0..1], and 'size' in [1..10] (default=5).
        if self.analyzed_graph is None:
            self._controller.deci.error("No graph provided to ProgressGraphWidget")
            return

        # Layout: graphviz "dot" if possible, else spring
        if HAS_PYGRAPHVIZ:
            pos = graphviz_layout(self.analyzed_graph, prog="dot")
        else:
            pos = nx.spring_layout(self.analyzed_graph)

        # Create a QGraphicsView
        view = GraphView(scene, self)

        # Build node items
        node_items = {}
        for func_node, data in self.analyzed_graph.nodes(data=True):
            hotness = data.get("hotness", 0.0)
            size_val = data.get("size", 5)
            x, y = pos[func_node]
            item = NodeItem(
                label_text=func_node.name,
                x=x,
                y=y,
                hotness=hotness,
                size=size_val,  # <--- scaled node
                view=view,
                controller=self._controller
            )
            scene.addItem(item)
            node_items[func_node] = item

        # Build edges
        for u, v, edata in self.analyzed_graph.edges(data=True):
            indirect = edata.get("indirect", False)
            edge_item = EdgeItem(node_items[u], node_items[v], indirect)
            scene.addItem(edge_item)
            node_items[u].add_edge(edge_item)
            node_items[v].add_edge(edge_item)

        main_layout.addWidget(view)
        self.setStyleSheet("background-color: #222222;")
        self.resize(1000, 800)

    def _analyze_graph(self, max_changes_heat=10) -> nx.DiGraph:
        # collect function changes
        func_changes_by_users = self._controller.compute_changes_per_function()
        func_changes = {}
        for func_addr, user_changes in func_changes_by_users.items():
            func_changes[func_addr] = sum(user_changes.values())
            _l.info(f"Function {hex(func_addr)} has {func_changes[func_addr]} changes")

        func_heats = {}
        # changed_funcs = set(func_addr for func_addr, changes in func_changes.items() if changes > 0)
        for func_addr, changes in func_changes.items():
            if changes > 0:
                func_heats[func_addr] = min(changes, max_changes_heat) / max_changes_heat

        # find the changed function nodes in the graph
        changed_func_nodes = set()
        for node in self._graph.nodes:
            if node.addr in func_heats:
                changed_func_nodes.add(node)

        func_nodes_in_graph = changed_func_nodes.copy()
        # find every node that is connected, dist of 1, from changed funcs
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
            node_data["hotness"] = func_heats.get(node.addr, 0.0)
            node_data["size"] = int(size_variances[node.size])

        return analyzed_graph

    def compute_size_outlier_scores(self, node_sizes: list[int], max_size=10) -> dict:
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
            variances[size] = (1 - score) * max_size

        return variances
