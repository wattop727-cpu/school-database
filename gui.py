"""
gui.py
------
Graphical User Interface for the Email Header Analyzer.
Uses: tkinter module, conditional statements, for loops,
      dictionaries, lists, tuples
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import queue

from analyzer import analyse_headers


# ── Colour palette ─────────────────────────────────────────────────────────
COLOURS = {
    "bg":          "#1e1e2e",
    "panel":       "#2a2a3d",
    "accent":      "#7c3aed",
    "accent_dark": "#5b21b6",
    "text":        "#e2e8f0",
    "subtext":     "#94a3b8",
    "pass":        "#22c55e",
    "fail":        "#ef4444",
    "softfail":    "#f59e0b",
    "neutral":     "#94a3b8",
    "low":         "#22c55e",
    "medium":      "#f59e0b",
    "high":        "#ef4444",
    "border":      "#3b3b52",
}

AUTH_COLOURS = {
    "pass":      COLOURS["pass"],
    "fail":      COLOURS["fail"],
    "softfail":  COLOURS["softfail"],
    "neutral":   COLOURS["neutral"],
    "none":      COLOURS["neutral"],
    "not found": COLOURS["neutral"],
    "unknown":   COLOURS["neutral"],
}

VERDICT_COLOURS = {
    "Low Risk":    COLOURS["low"],
    "Medium Risk": COLOURS["medium"],
    "High Risk":   COLOURS["high"],
}


class EmailHeaderAnalyzerApp:
    """Main Tkinter application class for the Email Header Analyzer."""

    def __init__(self, root):
        """
        Initialise the application window and all widgets.

        Parameters:
            root (tk.Tk): The root Tkinter window
        """
        self.root = root
        self.root.title("Email Header Analyzer")
        self.root.geometry("1100x780")
        self.root.configure(bg=COLOURS["bg"])
        self.root.resizable(True, True)

        # Queue for thread-safe communication between analysis thread and GUI
        self.result_queue = queue.Queue()

        self._build_ui()

    # ── UI Construction ────────────────────────────────────────────────────

    def _build_ui(self):
        """Build all UI sections: title bar, input panel, results panel."""
        self._build_title_bar()
        self._build_input_panel()
        self._build_results_panel()
        self._build_status_bar()

    def _build_title_bar(self):
        """Create the top title bar."""
        title_frame = tk.Frame(self.root, bg=COLOURS["accent"], height=55)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)

        tk.Label(
            title_frame,
            text="  🔍  Email Header Analyzer",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=COLOURS["accent"],
            anchor="w"
        ).pack(side="left", padx=20, pady=10)

        tk.Label(
            title_frame,
            text="Ethical Hacking & Cyber Security",
            font=("Segoe UI", 10),
            fg="#c4b5fd",
            bg=COLOURS["accent"]
        ).pack(side="right", padx=20)

    def _build_input_panel(self):
        """Create the header input area with paste box and action buttons."""
        input_frame = tk.Frame(self.root, bg=COLOURS["panel"], pady=12)
        input_frame.pack(fill="x", padx=15, pady=(12, 0))

        # Label
        tk.Label(
            input_frame,
            text="Paste Raw Email Header:",
            font=("Segoe UI", 10, "bold"),
            fg=COLOURS["text"],
            bg=COLOURS["panel"]
        ).pack(anchor="w", padx=12)

        # Scrollable text input
        self.header_input = scrolledtext.ScrolledText(
            input_frame,
            height=10,
            font=("Courier New", 9),
            bg="#12121f",
            fg=COLOURS["text"],
            insertbackground=COLOURS["text"],
            relief="flat",
            wrap="none"
        )
        self.header_input.pack(fill="x", padx=12, pady=6)

        # Buttons row
        btn_frame = tk.Frame(input_frame, bg=COLOURS["panel"])
        btn_frame.pack(fill="x", padx=12, pady=(0, 6))

        self._make_button(btn_frame, "▶  Analyse", self._run_analysis,
                          COLOURS["accent"], "white").pack(side="left", padx=(0, 8))

        self._make_button(btn_frame, "📂  Load File", self._load_file,
                          COLOURS["panel"], COLOURS["subtext"],
                          border=True).pack(side="left", padx=(0, 8))

        self._make_button(btn_frame, "🗑  Clear", self._clear_all,
                          COLOURS["panel"], COLOURS["subtext"],
                          border=True).pack(side="left")

        self._make_button(btn_frame, "💾  Export JSON", self._export_json,
                          COLOURS["panel"], COLOURS["subtext"],
                          border=True).pack(side="right")

    def _make_button(self, parent, text, command, bg, fg, border=False):
        """
        Helper to create a styled button.

        Parameters:
            parent: Parent widget
            text (str): Button label
            command: Callback function
            bg (str): Background colour
            fg (str): Foreground colour
            border (bool): Whether to show a border

        Returns:
            tk.Button: The created button widget
        """
        relief = "solid" if border else "flat"
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            font=("Segoe UI", 9, "bold"),
            relief=relief,
            bd=1 if border else 0,
            padx=12,
            pady=5,
            cursor="hand2",
            activebackground=COLOURS["accent_dark"],
            activeforeground="white"
        )
        return btn

    def _build_results_panel(self):
        """Create the tabbed results area."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=10)

        # Style the notebook
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",       background=COLOURS["bg"],  borderwidth=0)
        style.configure("TNotebook.Tab",   background=COLOURS["panel"],
                         foreground=COLOURS["subtext"],
                         padding=[14, 6],  font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", COLOURS["accent"])],
                  foreground=[("selected", "white")])

        # ── Tab 1: Summary ─────────────────────────────────────────────────
        self.tab_summary = tk.Frame(self.notebook, bg=COLOURS["bg"])
        self.notebook.add(self.tab_summary, text="  Summary  ")
        self._build_summary_tab()

        # ── Tab 2: Hop Trace ───────────────────────────────────────────────
        self.tab_hops = tk.Frame(self.notebook, bg=COLOURS["bg"])
        self.notebook.add(self.tab_hops, text="  Hop Trace  ")
        self._build_hops_tab()

        # ── Tab 3: Findings ────────────────────────────────────────────────
        self.tab_findings = tk.Frame(self.notebook, bg=COLOURS["bg"])
        self.notebook.add(self.tab_findings, text="  Detection Findings  ")
        self._build_findings_tab()

        # ── Tab 4: All Headers ─────────────────────────────────────────────
        self.tab_all = tk.Frame(self.notebook, bg=COLOURS["bg"])
        self.notebook.add(self.tab_all, text="  All Headers  ")
        self._build_all_headers_tab()

    def _build_summary_tab(self):
        """Build the Summary tab with key fields and authentication results."""
        outer = tk.Frame(self.tab_summary, bg=COLOURS["bg"])
        outer.pack(fill="both", expand=True, padx=15, pady=12)

        # ── Verdict banner ─────────────────────────────────────────────────
        self.verdict_frame = tk.Frame(outer, bg=COLOURS["panel"],
                                      pady=14, padx=20)
        self.verdict_frame.pack(fill="x", pady=(0, 12))

        self.verdict_label = tk.Label(
            self.verdict_frame,
            text="No analysis yet — paste a header above and click Analyse",
            font=("Segoe UI", 13, "bold"),
            fg=COLOURS["subtext"],
            bg=COLOURS["panel"]
        )
        self.verdict_label.pack()

        # ── Key fields ─────────────────────────────────────────────────────
        fields_frame = tk.LabelFrame(
            outer, text="  Key Header Fields  ",
            font=("Segoe UI", 9, "bold"),
            fg=COLOURS["subtext"], bg=COLOURS["panel"],
            bd=1, relief="solid"
        )
        fields_frame.pack(fill="x", pady=(0, 12))

        # Dictionary of label → StringVar for dynamic updating
        self.summary_vars = {}
        field_labels = ["From", "Reply-To", "Subject", "Date", "Message-ID", "Sending Domain"]

        for idx, label in enumerate(field_labels):         # for loop
            row = tk.Frame(fields_frame, bg=COLOURS["panel"])
            row.pack(fill="x", padx=12, pady=3)

            tk.Label(row, text=f"{label}:",
                     font=("Segoe UI", 9, "bold"),
                     fg=COLOURS["subtext"], bg=COLOURS["panel"],
                     width=16, anchor="w").pack(side="left")

            var = tk.StringVar(value="—")
            self.summary_vars[label] = var

            tk.Label(row, textvariable=var,
                     font=("Segoe UI", 9),
                     fg=COLOURS["text"], bg=COLOURS["panel"],
                     anchor="w").pack(side="left", fill="x", expand=True)

        # ── Authentication results ─────────────────────────────────────────
        auth_frame = tk.LabelFrame(
            outer, text="  Authentication Results (SPF / DKIM / DMARC)  ",
            font=("Segoe UI", 9, "bold"),
            fg=COLOURS["subtext"], bg=COLOURS["panel"],
            bd=1, relief="solid"
        )
        auth_frame.pack(fill="x")

        auth_inner = tk.Frame(auth_frame, bg=COLOURS["panel"])
        auth_inner.pack(padx=12, pady=10)

        self.auth_labels = {}   # dictionary of mechanism → label widget
        for mechanism in ["spf", "dkim", "dmarc"]:        # for loop
            col = tk.Frame(auth_inner, bg=COLOURS["panel"])
            col.pack(side="left", padx=25)

            tk.Label(col, text=mechanism.upper(),
                     font=("Segoe UI", 9, "bold"),
                     fg=COLOURS["subtext"], bg=COLOURS["panel"]).pack()

            result_label = tk.Label(col, text="—",
                                    font=("Segoe UI", 14, "bold"),
                                    fg=COLOURS["subtext"],
                                    bg=COLOURS["panel"])
            result_label.pack()
            self.auth_labels[mechanism] = result_label

    def _build_hops_tab(self):
        """Build the Hop Trace tab with a sortable treeview table."""
        frame = tk.Frame(self.tab_hops, bg=COLOURS["bg"])
        frame.pack(fill="both", expand=True, padx=15, pady=12)

        tk.Label(frame,
                 text="Mail Relay Hops — public IP addresses extracted from Received headers",
                 font=("Segoe UI", 9),
                 fg=COLOURS["subtext"], bg=COLOURS["bg"]).pack(anchor="w", pady=(0, 6))

        # Treeview
        style = ttk.Style()
        style.configure("Hops.Treeview",
                         background=COLOURS["panel"],
                         foreground=COLOURS["text"],
                         fieldbackground=COLOURS["panel"],
                         rowheight=26,
                         font=("Segoe UI", 9))
        style.configure("Hops.Treeview.Heading",
                         background=COLOURS["accent"],
                         foreground="white",
                         font=("Segoe UI", 9, "bold"))

        cols = ("Hop", "IP Address", "Raw Received Snippet")
        self.hops_tree = ttk.Treeview(frame, columns=cols,
                                       show="headings", style="Hops.Treeview")

        # Set column widths
        col_widths = {"Hop": 50, "IP Address": 140, "Raw Received Snippet": 700}
        for col in cols:                                   # for loop
            self.hops_tree.heading(col, text=col)
            self.hops_tree.column(col, width=col_widths[col], anchor="w")

        scrollbar = ttk.Scrollbar(frame, orient="vertical",
                                   command=self.hops_tree.yview)
        self.hops_tree.configure(yscrollcommand=scrollbar.set)

        self.hops_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_findings_tab(self):
        """Build the Detection Findings tab."""
        frame = tk.Frame(self.tab_findings, bg=COLOURS["bg"])
        frame.pack(fill="both", expand=True, padx=15, pady=12)

        tk.Label(frame,
                 text="Triggered detection rules — each rule contributes to the risk score",
                 font=("Segoe UI", 9),
                 fg=COLOURS["subtext"], bg=COLOURS["bg"]).pack(anchor="w", pady=(0, 6))

        # Score display
        score_frame = tk.Frame(frame, bg=COLOURS["panel"], pady=10, padx=16)
        score_frame.pack(fill="x", pady=(0, 10))

        self.score_label = tk.Label(
            score_frame,
            text="Risk Score: —",
            font=("Segoe UI", 12, "bold"),
            fg=COLOURS["text"], bg=COLOURS["panel"]
        )
        self.score_label.pack(side="left")

        # Findings listbox
        list_frame = tk.Frame(frame, bg=COLOURS["bg"])
        list_frame.pack(fill="both", expand=True)

        self.findings_listbox = tk.Listbox(
            list_frame,
            font=("Segoe UI", 10),
            bg=COLOURS["panel"],
            fg=COLOURS["text"],
            selectbackground=COLOURS["accent"],
            relief="flat",
            bd=0,
            activestyle="none"
        )
        scrollbar2 = ttk.Scrollbar(list_frame, orient="vertical",
                                    command=self.findings_listbox.yview)
        self.findings_listbox.configure(yscrollcommand=scrollbar2.set)

        self.findings_listbox.pack(side="left", fill="both", expand=True)
        scrollbar2.pack(side="right", fill="y")

    def _build_all_headers_tab(self):
        """Build the All Headers tab showing every parsed header field."""
        frame = tk.Frame(self.tab_all, bg=COLOURS["bg"])
        frame.pack(fill="both", expand=True, padx=15, pady=12)

        cols = ("Field Name", "Value")
        style = ttk.Style()
        style.configure("All.Treeview",
                         background=COLOURS["panel"],
                         foreground=COLOURS["text"],
                         fieldbackground=COLOURS["panel"],
                         rowheight=24,
                         font=("Courier New", 8))
        style.configure("All.Treeview.Heading",
                         background=COLOURS["accent"],
                         foreground="white",
                         font=("Segoe UI", 9, "bold"))

        self.all_tree = ttk.Treeview(frame, columns=cols,
                                      show="headings", style="All.Treeview")
        self.all_tree.heading("Field Name", text="Field Name")
        self.all_tree.heading("Value",      text="Value")
        self.all_tree.column("Field Name",  width=200)
        self.all_tree.column("Value",       width=800)

        sb = ttk.Scrollbar(frame, orient="vertical", command=self.all_tree.yview)
        self.all_tree.configure(yscrollcommand=sb.set)
        self.all_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def _build_status_bar(self):
        """Create the bottom status bar."""
        self.status_var = tk.StringVar(value="Ready — paste an email header and click Analyse")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Segoe UI", 8),
            fg=COLOURS["subtext"],
            bg=COLOURS["border"],
            anchor="w",
            padx=12,
            pady=4
        )
        status_bar.pack(fill="x", side="bottom")

    # ── Actions ────────────────────────────────────────────────────────────

    def _run_analysis(self):
        """Start the analysis in a background thread."""
        raw_text = self.header_input.get("1.0", tk.END).strip()

        if not raw_text:
            messagebox.showwarning("No Input",
                                   "Please paste a raw email header into the text box.")
            return

        # Basic validation using conditional statement
        if ":" not in raw_text:
            messagebox.showerror("Invalid Input",
                                 "This does not appear to be a valid email header.\n"
                                 "Email headers must contain field: value pairs.")
            return

        self._set_status("Analysing headers...")
        self._clear_results()

        # Run analysis in background thread so GUI stays responsive
        thread = threading.Thread(
            target=self._analysis_worker,
            args=(raw_text,),
            daemon=True
        )
        thread.start()
        self.root.after(100, self._check_queue)

    def _analysis_worker(self, raw_text):
        """
        Worker function that runs in a background thread.
        Puts result into the queue when done.

        Parameters:
            raw_text (str): Raw email header text to analyse
        """
        try:
            results = analyse_headers(raw_text)
            self.result_queue.put(("ok", results))
        except Exception as error:
            self.result_queue.put(("error", str(error)))

    def _check_queue(self):
        """Poll the result queue and update GUI when results are ready."""
        try:
            status, payload = self.result_queue.get_nowait()
            if status == "ok":
                self._populate_results(payload)
                self._set_status("Analysis complete.")
            else:
                messagebox.showerror("Analysis Error", f"An error occurred:\n{payload}")
                self._set_status("Analysis failed.")
        except queue.Empty:
            # Not ready yet — check again in 100ms (while loop equivalent)
            self.root.after(100, self._check_queue)

    def _load_file(self):
        """Load a .eml or .txt file into the input box."""
        filepath = filedialog.askopenfilename(
            title="Open Email Header File",
            filetypes=[("Email files", "*.eml"), ("Text files", "*.txt"),
                       ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self.header_input.delete("1.0", tk.END)
                self.header_input.insert("1.0", content)
                self._set_status(f"Loaded: {filepath}")
            except Exception as e:
                messagebox.showerror("File Error", str(e))

    def _export_json(self):
        """Export the last analysis results as a JSON file."""
        if not hasattr(self, "_last_results"):
            messagebox.showinfo("No Results", "Run an analysis first.")
            return

        import json
        filepath = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")]
        )
        if filepath:
            try:
                # Convert tuples in hops/findings to lists for JSON serialisation
                export_data = dict(self._last_results)
                export_data["hops"]     = [list(h) for h in export_data["hops"]]
                export_data["findings"] = [list(f) for f in export_data["findings"]]
                # Remove the full headers dict to keep file readable
                export_data.pop("all_headers", None)

                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2)
                self._set_status(f"Exported to {filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        """Clear the input box and all result panels."""
        self.header_input.delete("1.0", tk.END)
        self._clear_results()
        self._set_status("Cleared.")

    def _clear_results(self):
        """Reset all result widgets to their default empty state."""
        # Reset summary vars using for loop over dictionary
        for key, var in self.summary_vars.items():        # for loop
            var.set("—")

        # Reset auth labels
        for mechanism, label in self.auth_labels.items():  # for loop
            label.config(text="—", fg=COLOURS["subtext"])

        # Reset verdict
        self.verdict_label.config(
            text="Analysing...",
            fg=COLOURS["subtext"]
        )

        # Clear treeviews and listbox
        for item in self.hops_tree.get_children():
            self.hops_tree.delete(item)
        for item in self.all_tree.get_children():
            self.all_tree.delete(item)
        self.findings_listbox.delete(0, tk.END)
        self.score_label.config(text="Risk Score: —")

    # ── Results Population ─────────────────────────────────────────────────

    def _populate_results(self, results):
        """
        Populate all result tabs with data from the analysis.

        Parameters:
            results (dict): The full analysis results dictionary
        """
        self._last_results = results

        self._populate_summary(results)
        self._populate_hops(results)
        self._populate_findings(results)
        self._populate_all_headers(results)

        # Switch to Summary tab
        self.notebook.select(0)

    def _populate_summary(self, results):
        """Fill in the Summary tab fields and authentication results."""
        # Map results to summary fields using dictionary
        field_map = {
            "From":          results["from_raw"],
            "Reply-To":      results["reply_to"] or "—",
            "Subject":       results["subject"],
            "Date":          results["date"],
            "Message-ID":    results["message_id"],
            "Sending Domain": results["from_domain"] or "—",
        }

        for label, value in field_map.items():             # for loop
            self.summary_vars[label].set(value[:100] if value else "—")

        # Authentication results — conditional statements for colour
        auth = results["auth"]
        for mechanism, label_widget in self.auth_labels.items():  # for loop
            result = auth.get(mechanism, "not found")
            colour = AUTH_COLOURS.get(result, COLOURS["neutral"])
            label_widget.config(text=result.upper(), fg=colour)

        # Verdict banner
        verdict = results["verdict"]
        colour  = VERDICT_COLOURS.get(verdict, COLOURS["neutral"])
        score   = results["score"]
        self.verdict_label.config(
            text=f"⚠  {verdict}  (Risk Score: {score})",
            fg=colour
        )

    def _populate_hops(self, results):
        """Fill in the Hop Trace treeview."""
        hops = results["hops"]    # list of tuples

        if not hops:
            self.hops_tree.insert("", tk.END,
                                   values=("—", "No public IPs found in Received headers", ""))
            return

        for hop_tuple in hops:                             # for loop over list of tuples
            hop_num, ip, raw_line = hop_tuple              # tuple unpacking
            snippet = raw_line[:120] + "..." if len(raw_line) > 120 else raw_line
            self.hops_tree.insert("", tk.END, values=(hop_num, ip, snippet))

    def _populate_findings(self, results):
        """Fill in the Detection Findings listbox."""
        findings = results["findings"]   # list of tuples
        score    = results["score"]

        self.score_label.config(
            text=f"Risk Score: {score}  |  Verdict: {results['verdict']}"
        )

        if not findings:
            self.findings_listbox.insert(tk.END, "  ✅  No suspicious indicators detected.")
            self.findings_listbox.itemconfig(0, fg=COLOURS["pass"])
            return

        for finding_tuple in findings:                     # for loop over list of tuples
            rule_id, description, weight = finding_tuple  # tuple unpacking
            self.findings_listbox.insert(
                tk.END,
                f"  ⚠  [{weight:+d}]  {description}"
            )
            # Colour by weight using conditional statements
            last_idx = self.findings_listbox.size() - 1
            if weight >= 4:
                self.findings_listbox.itemconfig(last_idx, fg=COLOURS["fail"])
            elif weight >= 3:
                self.findings_listbox.itemconfig(last_idx, fg=COLOURS["softfail"])
            else:
                self.findings_listbox.itemconfig(last_idx, fg=COLOURS["neutral"])

    def _populate_all_headers(self, results):
        """Fill in the All Headers treeview."""
        all_headers = results["all_headers"]   # dictionary

        for field_name, field_value in all_headers.items():   # for loop over dict
            if isinstance(field_value, list):
                for val in field_value:                       # for loop
                    self.all_tree.insert("", tk.END,
                                         values=(field_name, str(val)[:200]))
            else:
                self.all_tree.insert("", tk.END,
                                     values=(field_name, str(field_value)[:200]))

    # ── Helper ─────────────────────────────────────────────────────────────

    def _set_status(self, message):
        """Update the status bar message."""
        self.status_var.set(message)
        self.root.update_idletasks()


# ── Entry point ────────────────────────────────────────────────────────────

def launch_gui():
    """Launch the Email Header Analyzer GUI application."""
    root = tk.Tk()
    app  = EmailHeaderAnalyzerApp(root)
    root.mainloop()
