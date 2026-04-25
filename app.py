# app.py — IP Reputation Pipeline Desktop UI
# Requires: PyQt5, pipeline.py and header.jpg in the same folder

import sys
import os
import sqlite3
import csv
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QFrame, QSplitter, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPixmap, QPainter

import pipeline


# ---------- Resource Path Helper ----------
# Finds bundled files whether running as python3 app.py or as a .app
# sys._MEIPASS only exists inside a PyInstaller bundle — it points to
# the temp folder where PyInstaller unpacked everything at launch.

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# ---------- Plain Text Paste Box ----------
# Overrides insertFromMimeData() so pasted text always loses its
# source formatting (black color, different fonts etc.) and inherits
# the stylesheet instead — keeping text white regardless of source.

class PlainTextEdit(QTextEdit):
    def insertFromMimeData(self, source):
        if source.hasText():
            self.insertPlainText(source.text())


# ---------- Header Widget ----------
# Custom QWidget that paints header.jpg as a background and overlays
# title text on top. paintEvent() is called by Qt every time the
# widget needs to redraw (resize, show, focus change, etc.)

class HeaderWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(140)
        self.bg = QPixmap(resource_path("header.jpg"))

        self.title = QLabel("IP Reputation Pipeline", self)
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setStyleSheet("""
            color: #ffffff; font-size: 26px; font-weight: bold;
            letter-spacing: 2px; background: transparent;
        """)

        self.subtitle = QLabel("AI-Enhanced Threat Intelligence  •  BLOCK / REVIEW / ALLOW", self)
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setStyleSheet("color: #94a3b8; font-size: 12px; background: transparent;")

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)

    def paintEvent(self, event):
        painter = QPainter(self)
        if not self.bg.isNull():
            scaled = self.bg.scaled(
                self.width(), self.height(),
                Qt.KeepAspectRatioByExpanding,
                Qt.SmoothTransformation
            )
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
        # Semi-transparent dark overlay so text is readable over the image
        painter.fillRect(self.rect(), QColor(0, 0, 0, 160))


# ---------- Background Worker Thread ----------
# Runs pipeline.process_ip_list() on a separate thread so the UI
# never freezes. Communicates back via PyQt signals — the only safe
# way to pass data from a background thread to the UI thread.

class PipelineWorker(QThread):
    progress = pyqtSignal(int, int)   # (current, total) — drives progress bar
    result_ready = pyqtSignal(list)   # list of result dicts when complete
    error_occurred = pyqtSignal(str)  # error message string on exception

    def __init__(self, ip_list, api_key, output_path):
        super().__init__()
        self.ip_list = ip_list
        self.api_key = api_key
        self.output_path = output_path

    def run(self):
        try:
            results = pipeline.process_ip_list(
                ip_list=self.ip_list,
                api_key=self.api_key,
                progress_callback=self.progress.emit,
                output_path=self.output_path
            )
            self.result_ready.emit(results)
        except Exception as e:
            self.error_occurred.emit(str(e))


# ---------- Main Window ----------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Reputation Pipeline")
        self.setMinimumSize(1100, 750)
        self.worker = None
        self.output_path = None
        self._build_ui()
        self._apply_styles()

    # ----------------------------------------------------------------
    # UI Construction
    # ----------------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(12)
        root.setContentsMargins(20, 20, 20, 20)

        # Header image — shared across both tabs, sits above the tab bar
        root.addWidget(HeaderWidget())
        root.addWidget(self._divider())

        # ---- QTabWidget ----
        # Acts as a container holding multiple pages (QWidgets).
        # addTab(widget, label) registers each page with a tab label.
        # currentChanged signal fires when the user switches tabs,
        # passing the index of the newly active tab (0=Pipeline, 1=History).
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_pipeline_tab(), "  ▶  Pipeline  ")
        self.tabs.addTab(self._build_history_tab(),  "  🗄  History   ")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self.tabs)

    # ----------------------------------------------------------------
    # Tab 1 — Pipeline
    # ----------------------------------------------------------------

    def _build_pipeline_tab(self):
        # Returns a QWidget containing the entire pipeline UI.
        # This widget becomes page 0 inside the QTabWidget.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 12, 0, 0)

        # API Key row
        key_row = QHBoxLayout()
        key_label = QLabel("AbuseIPDB API Key:")
        key_label.setFixedWidth(160)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Paste your API key here — it will not be saved")
        self.key_input.setEchoMode(QLineEdit.Password)
        show_btn = QPushButton("Show")
        show_btn.setFixedWidth(60)
        show_btn.setCheckable(True)
        show_btn.clicked.connect(self._toggle_key_visibility)
        key_row.addWidget(key_label)
        key_row.addWidget(self.key_input)
        key_row.addWidget(show_btn)
        layout.addLayout(key_row)

        # Splitter: IP input (left) | Results (right)
        splitter = QSplitter(Qt.Horizontal)

        # Left panel — IP input
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 8, 0)

        ip_label = QLabel("IP Addresses")
        ip_label.setObjectName("section_label")
        left_layout.addWidget(ip_label)

        ip_hint = QLabel("Paste one IP per line. Up to 1,000 IPs per run.")
        ip_hint.setObjectName("hint")
        left_layout.addWidget(ip_hint)

        self.ip_input = PlainTextEdit()
        self.ip_input.setPlaceholderText("192.168.1.1\n8.8.8.8\n1.2.3.4\n...")
        self.ip_input.setFont(QFont("Courier New", 10))
        left_layout.addWidget(self.ip_input)

        self.ip_count_label = QLabel("0 IPs entered")
        self.ip_count_label.setObjectName("hint")
        left_layout.addWidget(self.ip_count_label)
        self.ip_input.textChanged.connect(self._update_ip_count)

        clear_btn = QPushButton("Clear IPs")
        clear_btn.setObjectName("secondary_btn")
        clear_btn.clicked.connect(self._confirm_clear)
        left_layout.addWidget(clear_btn)

        splitter.addWidget(left_panel)

        # Right panel — Results table + detail panel
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 0, 0, 0)

        results_label = QLabel("Results")
        results_label.setObjectName("section_label")
        right_layout.addWidget(results_label)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP Address", "Decision", "Score", "Reasons"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(True)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        right_layout.addWidget(self.table)

        self.summary_label = QLabel("")
        self.summary_label.setObjectName("hint")
        right_layout.addWidget(self.summary_label)

        # Detail panel — shows full reasons for selected row
        detail_label = QLabel("Selected Row — Full Reasons")
        detail_label.setObjectName("section_label")
        right_layout.addWidget(detail_label)

        self.detail_panel = QTextEdit()
        self.detail_panel.setReadOnly(True)
        self.detail_panel.setFixedHeight(100)
        self.detail_panel.setPlaceholderText("Click any row above to see the full decision rationale here.")
        self.detail_panel.setFont(QFont("Courier New", 10))
        right_layout.addWidget(self.detail_panel)

        splitter.addWidget(right_panel)
        splitter.setSizes([350, 750])
        layout.addWidget(splitter)

        layout.addWidget(self._divider())

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        layout.addWidget(self.progress_bar)

        # Action buttons row
        btn_row = QHBoxLayout()
        self.save_path_label = QLabel("No output file selected")
        self.save_path_label.setObjectName("hint")
        btn_row.addWidget(self.save_path_label, stretch=1)

        choose_btn = QPushButton("Choose Save Location")
        choose_btn.setObjectName("secondary_btn")
        choose_btn.clicked.connect(self._choose_output_path)
        btn_row.addWidget(choose_btn)

        self.run_btn = QPushButton("▶  Run Pipeline")
        self.run_btn.setObjectName("run_btn")
        self.run_btn.clicked.connect(self._run_pipeline)
        btn_row.addWidget(self.run_btn)

        layout.addLayout(btn_row)

        return page

    # ----------------------------------------------------------------
    # Tab 2 — History & Database Manager
    # ----------------------------------------------------------------

    def _build_history_tab(self):
        # Returns a QWidget containing the entire history management UI.
        # This widget becomes page 1 inside the QTabWidget.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 12, 0, 0)

        # Top row: stats on the left, action buttons on the right
        top_row = QHBoxLayout()

        # Database stats label — populated by _refresh_history()
        self.db_stats_label = QLabel("Loading...")
        self.db_stats_label.setObjectName("hint")
        top_row.addWidget(self.db_stats_label, stretch=1)

        # Export button — saves entire history table to a CSV file
        export_btn = QPushButton("Export History to CSV")
        export_btn.setObjectName("secondary_btn")
        export_btn.clicked.connect(self._export_history)
        top_row.addWidget(export_btn)

        # Delete selected row button
        delete_btn = QPushButton("Delete Selected IP")
        delete_btn.setObjectName("secondary_btn")
        delete_btn.clicked.connect(self._delete_selected_ip)
        top_row.addWidget(delete_btn)

        # Wipe all — styled red to signal danger
        wipe_btn = QPushButton("⚠  Wipe All History")
        wipe_btn.setObjectName("danger_btn")
        wipe_btn.clicked.connect(self._wipe_all_history)
        top_row.addWidget(wipe_btn)

        layout.addLayout(top_row)

        # Search/filter bar
        # As the user types, _filter_history_table() runs live and hides
        # rows that don't match — no database query needed, just show/hide.
        search_row = QHBoxLayout()
        search_label = QLabel("Search:")
        search_label.setFixedWidth(60)
        self.history_search = QLineEdit()
        self.history_search.setPlaceholderText("Filter by IP address...")
        self.history_search.textChanged.connect(self._filter_history_table)
        search_row.addWidget(search_label)
        search_row.addWidget(self.history_search)
        layout.addLayout(search_row)

        # History table — 6 columns matching ip_history DB schema
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "IP Address", "First Seen", "Last Seen", "Times Seen", "Last Score", "Notes"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSortingEnabled(True)  # click any column header to sort
        layout.addWidget(self.history_table)

        return page

    # ----------------------------------------------------------------
    # Shared helpers
    # ----------------------------------------------------------------

    def _divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("divider")
        return line

    def _on_tab_changed(self, index):
        # Fires every time the user clicks a tab.
        # index 0 = Pipeline, index 1 = History.
        # When switching to History, we refresh the table automatically
        # so the user always sees up-to-date data without a manual reload.
        if index == 1:
            self._refresh_history()

    # ----------------------------------------------------------------
    # History tab logic
    # ----------------------------------------------------------------

    def _refresh_history(self):
        # Reads every row from ip_history.db and loads it into the
        # history table. Also updates the stats label at the top.
        # Called automatically when the user switches to the History tab.
        try:
            conn = sqlite3.connect(pipeline.CACHE_DB)
            cur = conn.cursor()
            cur.execute("SELECT ip, first_seen, last_seen, count, last_abuse_score, notes FROM ip_history ORDER BY last_seen DESC")
            rows = cur.fetchall()

            # Database stats
            cur.execute("SELECT COUNT(*) FROM ip_history")
            total = cur.fetchone()[0]

            cur.execute("SELECT MIN(first_seen) FROM ip_history")
            oldest = cur.fetchone()[0]

            conn.close()

            # File size of the database
            try:
                size_bytes = os.path.getsize(pipeline.CACHE_DB)
                if size_bytes < 1024:
                    size_str = f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes // 1024} KB"
                else:
                    size_str = f"{size_bytes // (1024 * 1024)} MB"
            except:
                size_str = "unknown"

            oldest_str = oldest[:10] if oldest else "N/A"  # trim to date only
            self.db_stats_label.setText(
                f"Total IPs stored: {total}   •   Oldest record: {oldest_str}   •   Database size: {size_str}"
            )

            # Populate the history table
            # setSortingEnabled must be disabled during population —
            # if left on, Qt re-sorts on every row insert which is slow
            # and causes visual glitches. Re-enable after all rows are set.
            self.history_table.setSortingEnabled(False)
            self.history_table.setRowCount(len(rows))

            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(row):
                    text = str(value) if value is not None else ""
                    # Trim timestamps to readable format: "2025-01-14 09:32"
                    if col_idx in (1, 2) and "T" in text:
                        text = text[:16].replace("T", " ")
                    item = QTableWidgetItem(text)
                    item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)

                    # Color the Last Score cell the same way decisions are colored
                    if col_idx == 4 and text:
                        try:
                            score = int(text)
                            if score >= pipeline.BLOCK_THRESHOLD:
                                item.setForeground(QColor("#ef4444"))  # red
                            elif score >= pipeline.REVIEW_THRESHOLD:
                                item.setForeground(QColor("#f59e0b"))  # amber
                            else:
                                item.setForeground(QColor("#22c55e"))  # green
                        except ValueError:
                            pass

                    self.history_table.setItem(row_idx, col_idx, item)

            self.history_table.setSortingEnabled(True)

        except Exception as e:
            self.db_stats_label.setText(f"Could not load history: {e}")

    def _filter_history_table(self, text):
        # Called live as the user types in the search box.
        # Iterates every row and hides any whose IP column doesn't contain
        # the search text. No database query — just show/hide existing rows.
        # Case-insensitive match using .lower().
        search = text.lower()
        for row in range(self.history_table.rowCount()):
            ip_item = self.history_table.item(row, 0)
            ip_text = ip_item.text().lower() if ip_item else ""
            self.history_table.setRowHidden(row, search not in ip_text)

    def _delete_selected_ip(self):
        # Gets the selected row, confirms with the user, then deletes
        # just that IP's row from the database and refreshes the table.
        selected = self.history_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "No Selection", "Please select an IP row to delete.")
            return

        row = self.history_table.currentRow()
        ip = self.history_table.item(row, 0).text() if self.history_table.item(row, 0) else ""

        reply = QMessageBox.question(
            self, "Delete IP History",
            f"Delete all history for:\n\n{ip}\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            conn = sqlite3.connect(pipeline.CACHE_DB)
            cur = conn.cursor()
            cur.execute("DELETE FROM ip_history WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            self._refresh_history()  # reload table after deletion
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not delete record:\n{e}")

    def _wipe_all_history(self):
        # Double confirmation before wiping — first popup warns, second
        # requires the user to explicitly confirm a destructive action.
        # Uses DELETE FROM (removes all rows) but keeps the table structure
        # intact so the app can immediately start writing new records.
        reply1 = QMessageBox.warning(
            self, "Wipe All History",
            "This will permanently delete ALL IP scan history.\n\n"
            "This action cannot be undone. Are you sure?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply1 != QMessageBox.Yes:
            return

        reply2 = QMessageBox.warning(
            self, "Final Confirmation",
            "Are you absolutely sure?\n\nAll historical data will be lost permanently.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply2 != QMessageBox.Yes:
            return

        try:
            conn = sqlite3.connect(pipeline.CACHE_DB)
            cur = conn.cursor()
            cur.execute("DELETE FROM ip_history")  # removes all rows, keeps table
            conn.commit()
            conn.close()
            self._refresh_history()
            QMessageBox.information(self, "Done", "All history has been wiped.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not wipe history:\n{e}")

    def _export_history(self):
        # Opens a save dialog, then writes every row from ip_history.db
        # to a CSV file at the chosen path.
        path, _ = QFileDialog.getSaveFileName(
            self, "Export History As", "ip_history_export.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        if not path.endswith(".csv"):
            path += ".csv"

        try:
            conn = sqlite3.connect(pipeline.CACHE_DB)
            cur = conn.cursor()
            cur.execute("SELECT ip, first_seen, last_seen, count, last_abuse_score, notes FROM ip_history ORDER BY last_seen DESC")
            rows = cur.fetchall()
            conn.close()

            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "First Seen", "Last Seen", "Times Seen", "Last Score", "Notes"])
                writer.writerows(rows)

            QMessageBox.information(self, "Export Complete", f"History exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Could not export history:\n{e}")

    # ----------------------------------------------------------------
    # Pipeline tab helpers
    # ----------------------------------------------------------------

    def _toggle_key_visibility(self, checked):
        self.key_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def _update_ip_count(self):
        lines = [l.strip() for l in self.ip_input.toPlainText().splitlines() if l.strip()]
        count = len(lines)
        over = count > 1000
        self.ip_count_label.setText(
            f"{'⚠ ' if over else ''}{count} IP{'s' if count != 1 else ''} entered"
            + (" — limit is 1,000 per run" if over else "")
        )

    def _confirm_clear(self):
        reply = QMessageBox.question(
            self, "Clear IPs",
            "Are you sure you want to clear all IP addresses?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.ip_input.clear()

    def _choose_output_path(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Results As", "ip_decisions.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if path:
            if not path.endswith(".csv"):
                path += ".csv"
            self.output_path = path
            filename = path.split("/")[-1].split("\\")[-1]
            self.save_path_label.setText(f"Saving to: {filename}")

    def _decision_color(self, decision):
        return {
            "BLOCK":  QColor("#ef4444"),
            "REVIEW": QColor("#f59e0b"),
            "ALLOW":  QColor("#22c55e"),
            "SKIP":   QColor("#64748b"),
        }.get(decision, QColor("#e2e8f0"))

    def _on_row_selected(self):
        # Fires when user clicks a pipeline results row.
        # Reads that row's data and displays full reasons in the detail panel.
        selected = self.table.selectedItems()
        if not selected:
            return
        row = self.table.currentRow()
        ip       = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
        decision = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
        score    = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
        reasons  = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
        reason_lines = "\n".join(
            f"  • {r.strip()}" for r in reasons.split(";") if r.strip()
        )
        self.detail_panel.setText(
            f"IP: {ip}    Decision: {decision}    Score: {score}\n\nReasons:\n{reason_lines}"
        )

    # ----------------------------------------------------------------
    # Pipeline execution
    # ----------------------------------------------------------------

    def _run_pipeline(self):
        api_key = self.key_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Missing API Key", "Please enter your AbuseIPDB API key.")
            return

        raw_text = self.ip_input.toPlainText().strip()
        if not raw_text:
            QMessageBox.warning(self, "No IPs", "Please paste at least one IP address.")
            return

        ip_list = [l.strip() for l in raw_text.splitlines() if l.strip()]

        if len(ip_list) > 1000:
            QMessageBox.warning(self, "Too Many IPs",
                f"You entered {len(ip_list)} IPs. The limit is 1,000 per run.")
            return

        if not self.output_path:
            self._choose_output_path()
            if not self.output_path:
                return

        self.table.setRowCount(0)
        self.table.sortByColumn(-1, Qt.AscendingOrder)
        self.detail_panel.clear()
        self.summary_label.setText("")
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting...")
        self.run_btn.setEnabled(False)
        self.run_btn.setText("Running...")

        self.worker = PipelineWorker(ip_list, api_key, self.output_path)
        self.worker.progress.connect(self._on_progress)
        self.worker.result_ready.connect(self._on_results)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, current, total):
        pct = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.progress_bar.setFormat(f"Processing {current} of {total}  ({pct}%)")

    def _on_results(self, results):
        self.run_btn.setEnabled(True)
        self.run_btn.setText("▶  Run Pipeline")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")

        self.table.setRowCount(len(results))
        counts = {"BLOCK": 0, "REVIEW": 0, "ALLOW": 0, "SKIP": 0}

        self.table.setSortingEnabled(False)

        for row_idx, r in enumerate(results):
            decision = r.get("decision", "")
            counts[decision] = counts.get(decision, 0) + 1
            ip_item     = QTableWidgetItem(r.get("ip", ""))
            dec_item    = QTableWidgetItem(decision)
            score_item  = QTableWidgetItem(str(r.get("score", "")))
            reason_item = QTableWidgetItem(r.get("reasons", ""))
            color = self._decision_color(decision)
            dec_item.setForeground(color)
            dec_item.setFont(QFont("", -1, QFont.Bold))
            for col, item in enumerate([ip_item, dec_item, score_item, reason_item]):
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                self.table.setItem(row_idx, col, item)

        self.table.setSortingEnabled(True)
        self.table.resizeRowsToContents()

        self.table.resizeRowsToContents()
        self.summary_label.setText(
            f"🔴 BLOCK: {counts['BLOCK']}   🟡 REVIEW: {counts['REVIEW']}   "
            f"🟢 ALLOW: {counts['ALLOW']}   ⚫ SKIP: {counts['SKIP']}"
        )
        QMessageBox.information(self, "Run Complete",
            f"Pipeline finished.\n\nBLOCK: {counts['BLOCK']}\nREVIEW: {counts['REVIEW']}\n"
            f"ALLOW: {counts['ALLOW']}\nSKIP: {counts['SKIP']}\n\nResults saved to:\n{self.output_path}"
        )

    def _on_error(self, message):
        self.run_btn.setEnabled(True)
        self.run_btn.setText("▶  Run Pipeline")
        self.progress_bar.setFormat("Error")
        QMessageBox.critical(self, "Pipeline Error", f"An error occurred:\n\n{message}")

    # ----------------------------------------------------------------
    # Styles
    # ----------------------------------------------------------------

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #0f1117; color: #e2e8f0; }

            QTabWidget::pane {
                border: none;
                background-color: #0f1117;
            }
            QTabBar::tab {
                background-color: #1e293b;
                color: #64748b;
                padding: 10px 20px;
                border: 1px solid #334155;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                font-size: 12px;
                font-weight: bold;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0f1117;
                color: #e2e8f0;
                border-bottom: 2px solid #2563eb;
            }
            QTabBar::tab:hover:!selected { background-color: #273549; color: #94a3b8; }

            QLabel#section_label { font-size: 13px; font-weight: bold; color: #94a3b8; letter-spacing: 1px; }
            QLabel#hint { font-size: 11px; color: #475569; }
            QFrame#divider { color: #1e293b; }

            QLineEdit, QTextEdit {
                background-color: #1e293b; border: 1px solid #334155;
                border-radius: 6px; padding: 8px; color: #e2e8f0; font-size: 12px;
            }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #3b82f6; }

            QPushButton {
                background-color: #1e293b; border: 1px solid #334155;
                border-radius: 6px; padding: 8px 14px; color: #94a3b8; font-size: 12px;
            }
            QPushButton:hover { background-color: #273549; color: #e2e8f0; }

            QPushButton#run_btn {
                background-color: #2563eb; border: none; color: #ffffff;
                font-size: 13px; font-weight: bold; padding: 10px 24px; min-width: 160px;
            }
            QPushButton#run_btn:hover { background-color: #1d4ed8; }
            QPushButton#run_btn:disabled { background-color: #1e3a5f; color: #475569; }

            QPushButton#danger_btn {
                background-color: #7f1d1d; border: 1px solid #ef4444;
                color: #fca5a5; font-size: 12px; font-weight: bold; padding: 8px 14px;
            }
            QPushButton#danger_btn:hover { background-color: #991b1b; color: #ffffff; }

            QTableWidget {
                background-color: #1e293b; border: 1px solid #334155;
                border-radius: 6px; gridline-color: #273549; font-size: 12px;
            }
            QTableWidget::item { padding: 6px; }
            QTableWidget::item:selected { background-color: #2563eb; color: #ffffff; }
            QHeaderView::section {
                background-color: #0f172a; color: #64748b; font-size: 11px;
                font-weight: bold; padding: 6px; border: none;
                border-bottom: 1px solid #334155; letter-spacing: 1px;
            }

            QProgressBar {
                background-color: #1e293b; border: 1px solid #334155;
                border-radius: 6px; height: 22px; text-align: center;
                color: #94a3b8; font-size: 11px;
            }
            QProgressBar::chunk { background-color: #2563eb; border-radius: 5px; }

            QScrollBar:vertical { background: #0f1117; width: 8px; }
            QScrollBar::handle:vertical { background: #334155; border-radius: 4px; }
        """)


# ---------- Entry Point ----------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
