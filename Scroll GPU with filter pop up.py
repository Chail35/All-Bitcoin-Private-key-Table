from PyQt5.QtWidgets import QApplication, QTableView, QVBoxLayout, QWidget, QHeaderView, QAbstractItemView, QAction, QStyledItemDelegate, QLineEdit, QHBoxLayout, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem
from PyQt5.QtGui import QKeySequence, QColor, QDesktopServices, QBrush, QPalette, QFont
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant, QModelIndex, QUrl
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58
import pyopencl as cl
import numpy as np
import os

os.environ["PYOPENCL_CTX"] = "0"

class MyModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.buffer_size = 100000000
        self.starting_point = int('0000000000000000000000000000000000000000000000000000000000000001', 16)
        self.buffer = list(range(self.starting_point, self.starting_point + self.buffer_size))
        self.addresses_c = {}  # Compressed addresses
        self.addresses_u = {}  # Uncompressed addresses
        self.target_addresses = set()
        self.load_target_addresses()  # Load target addresses from a file
        self.found_targets = set()  # Store found target addresses
        # OpenCL setup
        self.ctx = cl.create_some_context()
        self.queue = cl.CommandQueue(self.ctx)
        # Load and compile the OpenCL kernel
        with open("sha256.cl", "r") as kernel_file:
            kernel_source = kernel_file.read()
        self.program = cl.Program(self.ctx, kernel_source).build()
        # Filter text for each column
        self.filter_text = {
            0: "",  # Filter text for column 0
            1: "",  # Filter text for column 1
            2: "",  # Filter text for column 2
            3: "",  # Filter text for column 3
        }

    def load_target_addresses(self):
        with open("Target Addresses.txt", "r") as target_file:
            for line in target_file:
                self.target_addresses.add(line.strip())

    def calculate_sha256(self, private_key):
        # Convert private_key to bytes
        private_key_bytes = private_key.to_bytes(32, 'big')
        # Create OpenCL buffers for input and output data
        input_buffer = cl.Buffer(self.ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=private_key_bytes)
        output_buffer = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, 32)
        # Execute the OpenCL kernel
        self.program.func_sha256(self.queue, private_key_bytes.shape, None, input_buffer, output_buffer)
        # Read the result from the OpenCL buffer
        hash_result = np.empty(8, dtype=np.uint32)
        cl.enqueue_copy(self.queue, hash_result, output_buffer).wait()

        return hash_result

    def rowCount(self, parent=None):
        return len(self.buffer)

    def columnCount(self, parent=None):
        return 4

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            if index.column() == 0:
                value = str(self.buffer[index.row()])
            elif index.column() == 1:
                value = format(self.buffer[index.row()], '064x')
            elif index.column() in [2, 3]:
                hex_number = format(self.buffer[index.row()], '064x')
                key = SigningKey.from_string(bytes.fromhex(hex_number), curve=SECP256k1)
                public_key = key.get_verifying_key().to_string('compressed' if index.column() == 2 else 'uncompressed')
                h = hashlib.sha256(public_key).digest()
                r = hashlib.new('ripemd160', h).digest()
                value = base58.b58encode_check(b"\x00" + r).decode('utf-8')
                if index.column() == 2:
                    self.addresses_c[self.buffer[index.row()]] = value
                else:
                    self.addresses_u[self.buffer[index.row()]] = value
            # Apply filters based on filter_text
            if self.filter_text[index.column()] and self.filter_text[index.column()] not in value:
                return None  # Filtered out if the text doesn't match
            return value
        elif role == Qt.BackgroundRole:
            address = self.data(index, Qt.DisplayRole)
            if address in self.target_addresses and address not in self.found_targets:
                self.found_targets.add(address)
                private_key_hex = format(self.buffer[index.row()], '064x')
                message = f"Found target address: {address} - Private Key: {private_key_hex}"
                QMessageBox.information(None, "Target Address Found", message)
                print(message)  # Print to the terminal
                return QColor(Qt.white)  # Highlight the target address cell in white
        return QVariant()

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return ["Row Number", "Private Key Hex", "P2PKH(c)", "P2PKH(u)"][section]
        return QVariant()

    def canFetchMore(self, index):
        return not self.found_targets.issuperset(self.target_addresses)

    def fetchMore(self, index):
        if self.canFetchMore(index):
            self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount() + self.buffer_size - 1)
            self.starting_point += self.buffer_size
            new_data = list(range(self.starting_point, self.starting_point + self.buffer_size))
            self.buffer.extend(new_data)
            self.endInsertRows()
            if len(self.buffer) > self.buffer_size:
                self.beginRemoveRows(QModelIndex(), 0, self.buffer_size - 1)
                self.buffer = self.buffer[self.buffer_size:]
                self.endRemoveRows()

    def getFilteredData(self):
        # Initialize empty filtered data
        filtered_data = {0: [], 1: [], 2: [], 3: []}
        # Iterate over all data
        for i in range(self.rowCount()):
            for j in range(self.columnCount()):
                index = self.index(i, j)
                data = self.data(index, Qt.DisplayRole)
                # If data is not None, add it to the filtered data
                if data is not None:
                    filtered_data[j].append(data)
        return filtered_data

class AlternatingRowDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.row() % 2 == 0:
            option.backgroundBrush = QBrush(QColor(173, 216, 230))  # Light blue background for even rows
        else:
            option.backgroundBrush = QBrush(QColor(173, 216, 230))  # Blue background for odd rows
        # Make the font bold
        option.font.setBold(True)

class CustomTableView(QTableView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def resizeEvent(self, event):
        if self.model():
            max_compressed_address_length = max(len(self.model().addresses_c[address]) for address in self.model().addresses_c)
            max_uncompressed_address_length = max(len(self.model().addresses_u[address]) for address in self.model().addresses_u)
            max_length = max(max_compressed_address_length, max_uncompressed_address_length)
            
            if max_length > 0:
                for column in [2, 3]:  # Columns 2 and 3 (compressed and uncompressed addresses)
                    column_width = self.columnWidth(column)
                    new_column_width = max(column_width, max_length * 7)  # Adjust the factor (7) based on your font and style
                    self.setColumnWidth(column, new_column_width)
        super().resizeEvent(event)

class FilteredResultsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Row Number", "Private Key Hex", "P2PKH(c)", "P2PKH(u)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.verticalHeader().hide()
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 150)
        
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)

    def updateFilteredResults(self, filtered_data):
        self.table.setRowCount(0)
        for row in zip(*filtered_data.values()):
            self.table.insertRow(self.table.rowCount())
            for col, value in enumerate(row):
                item = QTableWidgetItem(value)
                self.table.setItem(self.table.rowCount() - 1, col, item)

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.table = CustomTableView()
        self.model = MyModel()
        self.table.setModel(self.model)
        delegate = AlternatingRowDelegate()  # Note the parentheses here
        self.table.setItemDelegate(delegate)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setColumnWidth(2, 150)  
        self.table.setColumnWidth(3, 150)  
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.clicked.connect(self.cellClicked)

        layout.addWidget(self.table)

        header_palette = QPalette()
        header_palette.setColor(QPalette.Window, QColor(79, 129, 189)) 
        self.table.horizontalHeader().setPalette(header_palette)

        selected_palette = QPalette()
        selected_palette.setColor(QPalette.Highlight, QColor(173, 216, 230)) 
        self.table.setPalette(selected_palette)

        self.filter_inputs = []
        for i in range(4):
            filter_input = QLineEdit(self)
            filter_input.setPlaceholderText(f"Filter Column {i}")
            filter_input.textChanged.connect(lambda text, col=i: self.applyFilter(col, text))
            self.filter_inputs.append(filter_input)

        filter_layout = QHBoxLayout()
        for filter_input in self.filter_inputs:
            filter_layout.addWidget(filter_input)

        layout.addLayout(filter_layout)

        # Add "Clear Filters" button
        clear_filters_btn = QPushButton("Clear Filters")
        clear_filters_btn.clicked.connect(self.clearFilters)
        layout.addWidget(clear_filters_btn)

        self.setLayout(layout)

        # Create and initialize the filtered results widget
        self.filtered_results_widget = FilteredResultsWidget()
        layout.addWidget(self.filtered_results_widget)
        self.filtered_results_widget.hide()  # Initially, hide the filtered results widget

    def cellClicked(self, index):
        if index.column() == 1:  # Check if the clicked cell is in column 1 (Private Key Hex)
            private_key_hex = index.data()
            if private_key_hex:
                # Construct the privatekeyfinder.io URL with the private key appended
                privatekeyfinder_url = f"https://privatekeyfinder.io/private-keys/bitcoin/?private-key={private_key_hex}"
                # Open the privatekeyfinder.io URL in the default web browser
                QDesktopServices.openUrl(QUrl(privatekeyfinder_url))
        elif index.column() in [2, 3]:  # Check if the clicked cell is in columns 2 or 3
            address = index.data()
            if address:
                # Construct the Blockchair URL with the clicked address
                blockchair_url = f"https://blockchair.com/bitcoin/address/{address}"
                # Open the Blockchair URL in the default web browser
                QDesktopServices.openUrl(QUrl(blockchair_url))

    def applyFilter(self, column, text):
        self.model.filter_text[column] = text
        self.model.layoutChanged.emit()
        if column == 2:  # Only update the filtered results widget for the "P2PKH(c)" column
            filtered_data = self.model.getFilteredData()
            self.filtered_results_widget.updateFilteredResults(filtered_data)
            if text:
                self.filtered_results_widget.show()
            else:
                self.filtered_results_widget.hide()

    def clearFilters(self):
        for column in range(4):
            self.model.filter_text[column] = ""
            self.filter_inputs[column].clear()
        self.model.layoutChanged.emit()
        self.filtered_results_widget.hide()  # Hide the filtered results widget when filters are cleared

app = QApplication([])
window = Window()
window.setWindowTitle("Bitcoin Address Table")
window.showMaximized()  # Maximize the main window
app.exec_()
