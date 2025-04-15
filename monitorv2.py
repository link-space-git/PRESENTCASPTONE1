import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import json
import getpass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from datetime import datetime

class FileMonitorEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        self.log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "file_monitor_logs"))
        self.current_user = getpass.getuser()  # Get current username
    
    def should_ignore(self, path):
        """Check if the path should be ignored (in our log directory)"""
        abs_path = os.path.abspath(path)
        return abs_path.startswith(self.log_dir)
    
    def log_action(self, action, path, dest_path=None):
        """Centralized logging with user and timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user = self.current_user
        if dest_path:
            message = f"[{timestamp}] User: {user} | {action}: {path} -> {dest_path}"
        else:
            message = f"[{timestamp}] User: {user} | {action}: {path}"
        self.gui.log_file_event(message, action.lower())
    
    def on_created(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("CREATED", event.src_path)
    
    def on_deleted(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("DELETED", event.src_path)
    
    def on_modified(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("MODIFIED", event.src_path)
    
    def on_moved(self, event):
        if not self.should_ignore(event.src_path) and (not hasattr(event, 'dest_path') or not self.should_ignore(event.dest_path)):
            self.log_action("MOVED", event.src_path, event.dest_path)

class BackupManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mitigating Databreach")
        self.root.geometry("1000x700")
        
        # Configuration
        self.source_dir = r'C:\1CAPSTONE\1_SYSTEM'
        self.backup_dir = r'C:\1CAPSTONE\Backup'
        self.default_backup = r'C:\1CAPSTONE\Backup\17032025_Backup'
        self.restore_target_dir = r'C:\1CAPSTONE\1_SYSTEM'
        
        # File monitoring variables
        self.monitoring = False
        self.observer = None
        self.monitor_path = r'D:\ '
        self.log_file_path = os.path.join(os.path.dirname(__file__), "file_monitor_logs")
        
        # Create log directory if it doesn't exist
        if not os.path.exists(self.log_file_path):
            os.makedirs(self.log_file_path)
        
        # Current log file
        self.current_log_file = os.path.join(
            self.log_file_path,
            f"file_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        # Initialize UI components
        self.setup_ui()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

    def setup_ui(self):
        """Initialize all UI components"""
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_backup_tab()
        self.create_scan_tab()
        self.create_restore_tab()
        self.create_monitor_tab()

    def select_source_dir(self):
        """Let user select source directory for backups"""
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.source_dir = dir_path
            self.source_dir_label.config(text=f"Source: {self.source_dir}")

    def select_backup_dir(self):
        """Let user select backup directory"""
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.backup_dir = dir_path
            self.backup_dir_label.config(text=f"Backup: {self.backup_dir}")
            self.refresh_backup_list()

    def select_system_dir_scan(self):
        """Let user select system directory for scanning"""
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.source_dir = dir_path
            self.system_dir_label.config(text=f"System: {self.source_dir}")

    def select_backup_dir_scan(self):
        """Let user select backup directory for scanning"""
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.default_backup = dir_path
            self.scan_backup_label.config(text=f"Backup: {self.default_backup}")

    def select_custom_backup(self):
        """Let user select a custom backup directory"""
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.default_backup = dir_path
            self.custom_backup_label.config(text=f"Custom Backup: {self.default_backup}")

    def select_restore_target(self):
        """Let user select restore target directory"""
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.restore_target_dir = dir_path
            self.restore_target_label.config(text=f"Restore Target: {self.restore_target_dir}")

    def create_backup(self):
        """Create a backup of the source directory"""
        backup_name = self.backup_name_entry.get().strip()
        if not backup_name:
            messagebox.showerror("Error", "Backup name is required!")
            return
        
        destination = os.path.join(self.backup_dir, backup_name)
        
        params = {
            "operation": "backup",
            "source_dir": self.source_dir,
            "destination_dir": destination
        }
        
        self.run_powershell_script(params)

    def quick_scan(self):
        """Perform a quick scan comparing system and backup directories"""
        if not os.path.exists(self.source_dir):
            messagebox.showerror("Error", "System directory does not exist!")
            return
        
        if not os.path.exists(self.default_backup):
            messagebox.showerror("Error", "Backup directory does not exist!")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, "Scanning... Please wait...\n", "info")
        self.root.update()
        
        params = {
            "operation": "scan",
            "system_dir": self.source_dir,
            "backup_dir": self.default_backup
        }
        
        self.run_powershell_script(params)

    def refresh_backup_list(self):
        """Refresh the list of available backups"""
        self.backup_listbox.delete(0, tk.END)
        if not os.path.exists(self.backup_dir):
            return
        
        backups = [name for name in os.listdir(self.backup_dir) 
                  if os.path.isdir(os.path.join(self.backup_dir, name))]
        
        for backup in sorted(backups):
            self.backup_listbox.insert(tk.END, backup)

    def restore_backup(self):
        """Restore from selected backup"""
        selected = self.backup_listbox.curselection()
        backup_path = ""
        
        if selected:
            backup_name = self.backup_listbox.get(selected[0])
            backup_path = os.path.join(self.backup_dir, backup_name)
        else:
            backup_path = self.default_backup
        
        if not backup_path or not os.path.exists(backup_path):
            messagebox.showerror("Error", "Please select a valid backup to restore")
            return
        
        if not self.restore_target_dir:
            messagebox.showerror("Error", "Please select a restore target directory")
            return
        
        self.restore_results.delete(1.0, tk.END)
        self.restore_results.insert(tk.END, f"Preparing to restore from:\n{backup_path}\nto:\n{self.restore_target_dir}\n\n", "info")
        self.root.update()
        
        params = {
            "operation": "restore",
            "backup_dir": backup_path,
            "system_dir": self.restore_target_dir
        }
        
        self.run_powershell_script(params)

    def run_powershell_script(self, params):
        """Execute PowerShell script with given parameters"""
        try:
            temp_json = os.path.join(os.environ['TEMP'], 'backup_params.json')
            with open(temp_json, 'w') as f:
                json.dump(params, f)
            
            script_path = os.path.join(os.path.dirname(__file__), "backup_operations.ps1")
            
            command = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", script_path,
                "-ParametersFile", temp_json
            ]
            
            self.update_status(f"Running {params['operation']} operation...")
            
            if params['operation'] in ['scan', 'restore']:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if params['operation'] == 'scan':
                    output_widget = self.scan_results
                else:
                    output_widget = self.restore_results
                
                output_widget.delete(1.0, tk.END)
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        if "DATABREACH" in output or "Error:" in output or "ERROR:" in output:
                            tag = "error"
                        elif "Warning:" in output:
                            tag = "warning"
                        elif "successful" in output or "complete" in output or "No differences" in output:
                            tag = "success"
                        else:
                            tag = "info"
                        
                        output_widget.insert(tk.END, output, tag)
                        output_widget.see(tk.END)
                        self.root.update()
                
                stderr = process.stderr.read()
                if stderr:
                    output_widget.insert(tk.END, f"\nERROR: {stderr}\n", "error")
                
            else:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if process.returncode == 0:
                    messagebox.showinfo("Success", f"{params['operation'].capitalize()} completed successfully!")
                    self.update_status("Operation completed successfully")
                    
                    if params['operation'] == 'backup':
                        self.refresh_backup_list()
                else:
                    messagebox.showerror("Error", f"Operation failed:\n{process.stderr}")
                    self.update_status("Operation failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run operation: {str(e)}")
            self.update_status("Error running operation")
            if params['operation'] in ['scan', 'restore']:
                if params['operation'] == 'scan':
                    self.scan_results.insert(tk.END, f"\nERROR: {str(e)}\n", "error")
                else:
                    self.restore_results.insert(tk.END, f"\nERROR: {str(e)}\n", "error")

    def apply_log_filters(self, event=None):
        """Apply the selected filters to the log display"""
        action_filter = self.filter_action_var.get()
        user_filter = self.filter_user_var.get().strip().lower()
        
        # Store the current scroll position
        scroll_position = self.monitor_log.yview()
        
        # Get all log content from the file, not just what's displayed
        try:
            with open(self.current_log_file, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
        except Exception as e:
            print(f"Error reading log file: {e}")
            return
        
        # Clear and repopulate with filtered content
        self.monitor_log.config(state=tk.NORMAL)  # Enable editing
        self.monitor_log.delete(1.0, tk.END)
        
        for line in all_lines:
            if not line.strip():
                continue
                
            include = True
            
            # Apply action filter
            if action_filter != "ALL":
                if not any([
                    f"| {action_filter}:" in line,
                    line.startswith('[') and action_filter == "ALL"
                ]):
                    include = False
            
            # Apply user filter
            if user_filter:
                if f"user: {user_filter}" not in line.lower():
                    include = False
            
            if include:
                # Determine the tag based on action type
                if "| created:" in line.lower():
                    tag = "created"
                elif "| deleted:" in line.lower():
                    tag = "deleted"
                elif "| modified:" in line.lower():
                    tag = "modified"
                elif "| moved:" in line.lower():
                    tag = "moved"
                else:
                    tag = ""
                
                self.monitor_log.insert(tk.END, line, tag)
        
        # Restore scroll position
        self.monitor_log.yview_moveto(scroll_position[0])
        self.monitor_log.config(state=tk.DISABLED)  # Disable editing

    def clear_log_filters(self):
        """Clear all filters and show full log"""
        self.filter_action_var.set("ALL")
        self.filter_user_var.set("")
        self.apply_log_filters()

    def browse_monitor_dir(self):
        directory = filedialog.askdirectory(initialdir=self.monitor_path)
        if directory:
            self.monitor_path = directory
            self.monitor_path_entry.delete(0, tk.END)
            self.monitor_path_entry.insert(0, directory)
            # Restart monitoring with new directory
            self.stop_file_monitoring()
            self.start_file_monitoring()
    
    def log_file_event(self, message, event_type=""):
        """Log file event to both the GUI and the log file"""
        # Write to log file
        try:
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                f.write(message + '\n')
        except Exception as e:
            print(f"Error writing to log file: {e}")
        
        # Apply current filters to determine if we should display
        action_filter = self.filter_action_var.get()
        user_filter = self.filter_user_var.get().strip().lower()
        
        include = True
        if action_filter != "ALL" and f"| {action_filter}:" not in message:
            include = False
        if user_filter and f"user: {user_filter}" not in message.lower():
            include = False
        
        if include:
            # Determine the tag based on action type
            if "| created:" in message.lower():
                tag = "created"
            elif "| deleted:" in message.lower():
                tag = "deleted"
            elif "| modified:" in message.lower():
                tag = "modified"
            elif "| moved:" in message.lower():
                tag = "moved"
            else:
                tag = ""
            
            self.monitor_log.config(state=tk.NORMAL)
            self.monitor_log.insert(tk.END, message + '\n', tag)
            self.monitor_log.see(tk.END)
            self.monitor_log.config(state=tk.DISABLED)
            self.monitor_log.update()
    
    def view_log_history(self):
        """Open a window showing available log files"""
        history_window = tk.Toplevel(self.root)
        history_window.title("File Monitor Log History")
        history_window.geometry("600x400")
        
        # List of log files
        log_files = []
        if os.path.exists(self.log_file_path):
            log_files = sorted(
                [f for f in os.listdir(self.log_file_path) if f.endswith(".log")],
                reverse=True
            )
        
        if not log_files:
            tk.Label(history_window, text="No log files found").pack(pady=20)
            return
        
        # Listbox with scrollbar
        frame = tk.Frame(history_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        listbox.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=listbox.yview)
        
        for log_file in log_files:
            listbox.insert(tk.END, log_file)
        
        # View button
        def view_selected_log():
            selection = listbox.curselection()
            if selection:
                selected_file = os.path.join(self.log_file_path, listbox.get(selection[0]))
                self.display_log_file(selected_file)
        
        button_frame = tk.Frame(history_window)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="View Selected Log", 
                 command=view_selected_log).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Delete Selected Log", 
                 command=lambda: self.delete_log_file(listbox)).pack(side=tk.LEFT, padx=5)
    
    def display_log_file(self, file_path):
        """Display the contents of a log file in a new window"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            log_window = tk.Toplevel(self.root)
            log_window.title(f"Log File: {os.path.basename(file_path)}")
            log_window.geometry("800x600")
            
            text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text.insert(tk.END, content)
            text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read log file: {e}")
    
    def delete_log_file(self, listbox):
        """Delete the selected log file"""
        selection = listbox.curselection()
        if not selection:
            return
            
        file_name = listbox.get(selection[0])
        file_path = os.path.join(self.log_file_path, file_name)
        
        try:
            os.remove(file_path)
            listbox.delete(selection[0])
            messagebox.showinfo("Success", f"Deleted log file: {file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete file: {e}")
    
    def open_current_log(self):
        """Open the current log file in the default text editor"""
        try:
            if os.path.exists(self.current_log_file):
                os.startfile(self.current_log_file)
            else:
                messagebox.showinfo("Info", "No log entries yet in current session")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")
    
    def start_file_monitoring(self):
        path = self.monitor_path_entry.get().strip() if self.monitor_path_entry else self.monitor_path
        
        if not path:
            self.log_file_event("Error: No directory specified", "error")
            return
            
        if not os.path.isdir(path):
            self.log_file_event(f"Error: Directory not found - {path}", "error")
            return
            
        if self.monitoring:
            self.stop_file_monitoring()
        
        # Create new log file for this monitoring session
        self.current_log_file = os.path.join(
            self.log_file_path,
            f"file_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        self.event_handler = FileMonitorEventHandler(self)
        self.observer = Observer()
        
        try:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            self.start_monitor_btn.config(state="disabled")
            self.stop_monitor_btn.config(state="normal")
            self.log_file_event(f"Started monitoring directory: {path}", "info")
            self.log_file_event("Watching for file changes...", "info")
        except Exception as e:
            self.log_file_event(f"Error starting monitor: {str(e)}", "error")
    
    def stop_file_monitoring(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
                self.log_file_event("Monitoring stopped", "info")
            except Exception as e:
                self.log_file_event(f"Error stopping monitor: {str(e)}", "error")
            finally:
                self.observer = None
                
        self.monitoring = False
        self.start_monitor_btn.config(state="normal")
        self.stop_monitor_btn.config(state="disabled")

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def create_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup")
        
        tk.Label(tab, text="Backup Name:").pack(pady=5)
        self.backup_name_entry = tk.Entry(tab, width=40)
        self.backup_name_entry.pack(pady=5)
        
        tk.Button(tab, text="Select Source Directory", 
                 command=self.select_source_dir).pack(pady=5)
        self.source_dir_label = tk.Label(tab, text=f"Source: {self.source_dir}")
        self.source_dir_label.pack(pady=5)
        
        tk.Button(tab, text="Select Backup Directory", 
                 command=self.select_backup_dir).pack(pady=5)
        self.backup_dir_label = tk.Label(tab, text=f"Backup: {self.backup_dir}")
        self.backup_dir_label.pack(pady=5)
        
        tk.Button(tab, text="Create Backup", 
                 command=self.create_backup, bg="lightblue").pack(pady=20)

    def create_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Scan")
        
        tk.Label(tab, text="System Directory:").pack(pady=5)
        tk.Button(tab, text="Select System Directory", 
                command=self.select_system_dir_scan).pack(pady=5)
        self.system_dir_label = tk.Label(tab, text=f"System: {self.source_dir}")
        self.system_dir_label.pack(pady=5)
        
        tk.Label(tab, text="Backup Directory:").pack(pady=5)
        tk.Button(tab, text="Select Backup Directory", 
                command=self.select_backup_dir_scan).pack(pady=5)
        self.scan_backup_label = tk.Label(tab, text=f"Backup: {self.default_backup}")
        self.scan_backup_label.pack(pady=5)
        
        tk.Button(tab, text="Run Scan", 
                 command=self.quick_scan, bg="lightgreen").pack(pady=20)
        
        results_frame = tk.Frame(tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(results_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.scan_results = tk.Text(results_frame, height=15, wrap=tk.WORD, 
                                  yscrollcommand=scrollbar.set)
        self.scan_results.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=self.scan_results.yview)
        
        self.scan_results.tag_config("error", foreground="red")
        self.scan_results.tag_config("success", foreground="green")
        self.scan_results.tag_config("warning", foreground="orange")
        self.scan_results.tag_config("info", foreground="blue")
        
        self.scan_results.insert(tk.END, "Scan results will appear here...\n", "info")

    def create_restore_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Restore")
        
        tk.Label(tab, text="Select Backup to Restore:").pack(pady=5)
        
        backup_list_frame = tk.Frame(tab)
        backup_list_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.backup_listbox = tk.Listbox(backup_list_frame, height=8)
        self.backup_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(backup_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.backup_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.backup_listbox.yview)
        
        self.refresh_backup_list()
        
        tk.Button(tab, text="Select Custom Backup Directory", 
                 command=self.select_custom_backup).pack(pady=5)
        self.custom_backup_label = tk.Label(tab, text="Custom Backup: Not selected")
        self.custom_backup_label.pack(pady=5)
        
        tk.Button(tab, text="Select Restore Target Directory", 
                 command=self.select_restore_target).pack(pady=5)
        self.restore_target_label = tk.Label(tab, text=f"Restore Target: {self.restore_target_dir}")
        self.restore_target_label.pack(pady=5)
        
        button_frame = tk.Frame(tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Refresh Backup List", 
                 command=self.refresh_backup_list).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Restore Selected Backup", 
                 command=self.restore_backup, bg="lightcoral").pack(side=tk.LEFT, padx=5)
        
        self.restore_results = tk.Text(tab, height=8, wrap=tk.WORD)
        self.restore_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.restore_results.tag_config("error", foreground="red")
        self.restore_results.tag_config("success", foreground="green")
        self.restore_results.insert(tk.END, "Restore results will appear here...\n", "info")

    def create_monitor_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="File Monitor")
        
        # Path selection frame
        path_frame = ttk.LabelFrame(tab, text="Monitor Directory")
        path_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(path_frame, text="Directory:").pack(side="left", padx=5)
        
        self.monitor_path_entry = ttk.Entry(path_frame, width=50)
        self.monitor_path_entry.insert(0, self.monitor_path)
        self.monitor_path_entry.pack(side="left", expand=True, fill="x", padx=5)
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_monitor_dir)
        browse_btn.pack(side="left", padx=5)
        
        # Filter controls frame
        filter_frame = ttk.LabelFrame(tab, text="Log Filters")
        filter_frame.pack(pady=5, padx=10, fill="x")
        
        ttk.Label(filter_frame, text="Filter by action:").pack(side="left", padx=5)
        
        # Action filter dropdown
        self.filter_action_var = tk.StringVar()
        self.filter_action_var.set("ALL")  # Default show all
        filter_dropdown = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_action_var,
            values=["ALL", "CREATED", "MODIFIED", "DELETED", "MOVED"],
            state="readonly",
            width=12
        )
        filter_dropdown.pack(side="left", padx=5)
        filter_dropdown.bind("<<ComboboxSelected>>", self.apply_log_filters)
        
        # User filter entry
        ttk.Label(filter_frame, text="Filter by user:").pack(side="left", padx=5)
        self.filter_user_var = tk.StringVar()
        user_entry = ttk.Entry(filter_frame, textvariable=self.filter_user_var, width=15)
        user_entry.pack(side="left", padx=5)
        
        # Apply filters button
        ttk.Button(filter_frame, text="Apply Filters", 
                  command=self.apply_log_filters).pack(side="left", padx=5)
        
        # Clear filters button
        ttk.Button(filter_frame, text="Clear Filters", 
                  command=self.clear_log_filters).pack(side="left", padx=5)
        
        # Log management frame
        log_manage_frame = ttk.Frame(tab)
        log_manage_frame.pack(pady=5, fill="x")
        
        ttk.Button(log_manage_frame, text="View Log History", 
                  command=self.view_log_history).pack(side="left", padx=5)
        ttk.Button(log_manage_frame, text="Open Current Log", 
                  command=self.open_current_log).pack(side="left", padx=5)
        
        # Control buttons frame
        control_frame = ttk.Frame(tab)
        control_frame.pack(pady=5, fill="x")
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                          command=self.start_file_monitoring)
        self.start_monitor_btn.pack(side="left", padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                         command=self.stop_file_monitoring, state="disabled")
        self.stop_monitor_btn.pack(side="left", padx=5)
        
        # Log frame
        log_frame = ttk.LabelFrame(tab, text="File Activity Log")
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20)
        self.monitor_log.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Configure tags for different message types
        self.monitor_log.tag_config("created", foreground="blue")
        self.monitor_log.tag_config("deleted", foreground="red")
        self.monitor_log.tag_config("modified", foreground="orange")
        self.monitor_log.tag_config("moved", foreground="green")
        
        self.monitor_log.insert(tk.END, "File monitoring log will appear here...\n")

    def on_closing(self):
        self.stop_file_monitoring()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = BackupManagerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()