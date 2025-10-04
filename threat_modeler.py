#!/usr/bin/env python3
"""
Threat Modeler GUI — single-window app.

Features:
- Assets (value 1..5), Attack Surfaces, Adversaries management
- Create threats linking asset + attack surface + adversary with description, likelihood (1..5),
  mitigation, and mitigation validation
- Mitigation & Mitigation Validation are editable comboboxes seeded by distinct existing values
- Live multi-keyword filter with placeholder (filters as you type)
- Risk = asset.value * likelihood shown as a column
- Severity (Low/Medium/High/Critical) color-coded
- Sortable & filterable threats table
- Export threats table to CSV
- Import/Export whole dataset as JSON
- Threat matrix (requires matplotlib & numpy)
"""

import csv
import json
import uuid
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from dataclasses import dataclass, asdict, field
from typing import Dict, Optional

# Optional visualization dependencies
try:
    import matplotlib
    matplotlib.use('Agg')  # safe backend fallback; TkAgg will be used when embedding
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False

# ---------------- Data model ----------------
@dataclass
class Asset:
    id: str
    name: str
    value: int

@dataclass
class AttackSurface:
    id: str
    name: str

@dataclass
class Adversary:
    id: str
    name: str

@dataclass
class Threat:
    id: str
    asset_id: str
    attack_surface_id: str
    adversary_id: str
    description: str
    likelihood: int
    mitigation: str
    mitigation_validation: str

    def calculate_risk(self, model: 'DataModel') -> int:
        a = model.assets.get(self.asset_id)
        if not a:
            return 0
        try:
            return int(a.value) * int(self.likelihood)
        except Exception:
            return 0

    def risk_severity(self, model: 'DataModel') -> str:
        r = self.calculate_risk(model)
        if r <= 5:
            return 'Low'
        elif r <= 12:
            return 'Medium'
        elif r <= 20:
            return 'High'
        else:
            return 'Critical'

@dataclass
class DataModel:
    assets: Dict[str, Asset] = field(default_factory=dict)
    attack_surfaces: Dict[str, AttackSurface] = field(default_factory=dict)
    adversaries: Dict[str, Adversary] = field(default_factory=dict)
    threats: Dict[str, Threat] = field(default_factory=dict)

    def to_json(self) -> str:
        payload = {
            'assets': [asdict(a) for a in self.assets.values()],
            'attack_surfaces': [asdict(a) for a in self.attack_surfaces.values()],
            'adversaries': [asdict(a) for a in self.adversaries.values()],
            'threats': [asdict(t) for t in self.threats.values()],
        }
        return json.dumps(payload, indent=2)

    @classmethod
    def from_json(cls, s: str) -> 'DataModel':
        obj = json.loads(s)
        dm = cls()
        for a in obj.get('assets', []):
            dm.assets[a['id']] = Asset(**a)
        for a in obj.get('attack_surfaces', []):
            dm.attack_surfaces[a['id']] = AttackSurface(**a)
        for a in obj.get('adversaries', []):
            dm.adversaries[a['id']] = Adversary(**a)
        for t in obj.get('threats', []):
            dm.threats[t['id']] = Threat(**t)
        return dm

def newid() -> str:
    return str(uuid.uuid4())

# ---------------- Generic List Editor ----------------
class ListEditor(tk.Frame):
    def __init__(self, master, title: str, columns: list, get_items_cb, add_cb, edit_cb, delete_cb):
        super().__init__(master)
        self.get_items_cb = get_items_cb
        self.add_cb = add_cb
        self.edit_cb = edit_cb
        self.delete_cb = delete_cb

        ttk.Label(self, text=title).pack(anchor='w')
        self.tree = ttk.Treeview(self, columns=columns, show='headings', height=6)
        for c in columns:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140)
        self.tree.pack(fill='both', expand=True)
        btnf = ttk.Frame(self)
        ttk.Button(btnf, text='Add', command=self.on_add).pack(side='left')
        ttk.Button(btnf, text='Edit', command=self.on_edit).pack(side='left')
        ttk.Button(btnf, text='Delete', command=self.on_delete).pack(side='left')
        btnf.pack(anchor='e', pady=3)
        self.refresh()

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for it in self.get_items_cb():
            vals = tuple(getattr(it, col) for col in self.tree['columns'])
            self.tree.insert('', 'end', iid=it.id, values=vals)

    def on_add(self):
        self.add_cb(); self.refresh()

    def on_edit(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an item to edit')
            return
        self.edit_cb(sel[0]); self.refresh()

    def on_delete(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an item to delete')
            return
        if messagebox.askyesno('Confirm', 'Delete selected item?'):
            self.delete_cb(sel[0]); self.refresh()

# ---------------- Threat Editor (with dynamic comboboxes) ----------------
class ThreatEditor(tk.Frame):
    def __init__(self, master, model: DataModel, on_change_cb):
        super().__init__(master)
        self.model = model
        self.on_change_cb = on_change_cb

        frm = ttk.LabelFrame(self, text='Create / Edit Threat')
        frm.pack(fill='x', padx=4, pady=4)

        ttk.Label(frm, text='Asset:').grid(row=0, column=0, sticky='e')
        self.asset_cb = ttk.Combobox(frm, state='readonly', width=28)
        self.asset_cb.grid(row=0, column=1, sticky='we')
        ttk.Label(frm, text='Value:').grid(row=0, column=2, sticky='e')
        self.asset_value_lbl = ttk.Label(frm, text='', width=4)
        self.asset_value_lbl.grid(row=0, column=3, sticky='w')

        ttk.Label(frm, text='Attack Surface:').grid(row=1, column=0, sticky='e')
        self.as_cb = ttk.Combobox(frm, state='readonly', width=28)
        self.as_cb.grid(row=1, column=1, sticky='we')

        ttk.Label(frm, text='Adversary:').grid(row=2, column=0, sticky='e')
        self.adv_cb = ttk.Combobox(frm, state='readonly', width=28)
        self.adv_cb.grid(row=2, column=1, sticky='we')

        ttk.Label(frm, text='Threat:').grid(row=3, column=0, sticky='ne')
        self.desc_txt = tk.Text(frm, height=3, width=60)
        self.desc_txt.grid(row=3, column=1, columnspan=3, sticky='we')

        ttk.Label(frm, text='Likelihood (1-5):').grid(row=4, column=0, sticky='e')
        self.lik_spin = ttk.Spinbox(frm, from_=1, to=5, width=5)
        self.lik_spin.grid(row=4, column=1, sticky='w')

        ttk.Label(frm, text='Mitigation:').grid(row=5, column=0, sticky='ne')
        # editable combobox (default state='normal' allows typing)
        self.mit_combo = ttk.Combobox(frm, state='normal', width=58)
        self.mit_combo.grid(row=5, column=1, columnspan=3, sticky='we')

        ttk.Label(frm, text='Mitigation Validation:').grid(row=6, column=0, sticky='ne')
        self.val_combo = ttk.Combobox(frm, state='normal', width=58)
        self.val_combo.grid(row=6, column=1, columnspan=3, sticky='we')

        btnfrm = ttk.Frame(frm)
        ttk.Button(btnfrm, text='Add / Save Threat', command=self.add_threat).pack(side='left')
        ttk.Button(btnfrm, text='Clear', command=self.clear_inputs).pack(side='left')
        btnfrm.grid(row=7, column=1, sticky='w', pady=4)

        frm.columnconfigure(1, weight=1)
        self.selected_threat_id: Optional[str] = None

        # live combobox refresh and asset value update
        self.refresh_comboboxes()
        self.asset_cb.bind('<<ComboboxSelected>>', lambda e: self.update_asset_value_label())
        self.lik_spin.bind('<KeyRelease>', lambda e: None)  # placeholder if we later want live updates

    def refresh_comboboxes(self):
        # assets
        assets = list(self.model.assets.values())
        self.asset_map = {a.name: a.id for a in assets}
        self.asset_cb['values'] = list(self.asset_map.keys())

        # attack surfaces
        as_list = list(self.model.attack_surfaces.values())
        self.as_map = {a.name: a.id for a in as_list}
        self.as_cb['values'] = list(self.as_map.keys())

        # adversaries
        advs = list(self.model.adversaries.values())
        self.adv_map = {a.name: a.id for a in advs}
        self.adv_cb['values'] = list(self.adv_map.keys())

        # dynamic mitigation / validation lists (distinct values from existing threats)
        mitigations = sorted({t.mitigation for t in self.model.threats.values() if t.mitigation})
        validations = sorted({t.mitigation_validation for t in self.model.threats.values() if t.mitigation_validation})
        self.mit_combo['values'] = mitigations
        self.val_combo['values'] = validations

    def update_asset_value_label(self):
        name = self.asset_cb.get()
        aid = self.asset_map.get(name)
        if aid:
            a = self.model.assets.get(aid)
            if a:
                self.asset_value_lbl.config(text=str(a.value))
                return
        self.asset_value_lbl.config(text='')

    def add_threat(self):
        asset_key = self.asset_cb.get()
        as_key = self.as_cb.get()
        adv_key = self.adv_cb.get()
        if not asset_key or not as_key or not adv_key:
            messagebox.showerror('Missing', 'Select asset, attack surface and adversary')
            return
        asset_id = self.asset_map[asset_key]
        as_id = self.as_map[as_key]
        adv_id = self.adv_map[adv_key]
        desc = self.desc_txt.get('1.0', 'end').strip()
        if not desc:
            messagebox.showerror('Missing', 'Enter a threat description')
            return
        try:
            lik = int(self.lik_spin.get())
        except Exception:
            lik = 1
        mit = (self.mit_combo.get() or '').strip()
        val = (self.val_combo.get() or '').strip()

        if self.selected_threat_id:
            tid = self.selected_threat_id
        else:
            tid = newid()
        t = Threat(id=tid, asset_id=asset_id, attack_surface_id=as_id, adversary_id=adv_id,
                   description=desc, likelihood=lik, mitigation=mit, mitigation_validation=val)
        self.model.threats[t.id] = t
        # refresh mitigation/validation values immediately so future entries include this one
        self.clear_inputs()
        self.on_change_cb()

    def clear_inputs(self):
        self.selected_threat_id = None
        self.asset_cb.set('')
        self.asset_value_lbl.config(text='')
        self.as_cb.set('')
        self.adv_cb.set('')
        self.desc_txt.delete('1.0', 'end')
        self.lik_spin.set(1)
        self.mit_combo.set('')
        self.val_combo.set('')

    def edit_threat(self, threat_id: str):
        t = self.model.threats.get(threat_id)
        if not t:
            return
        asset = self.model.assets.get(t.asset_id)
        if asset:
            self.asset_cb.set(asset.name)
            self.asset_value_lbl.config(text=str(asset.value))
        else:
            self.asset_cb.set('')
            self.asset_value_lbl.config(text='')
        asf = self.model.attack_surfaces.get(t.attack_surface_id)
        if asf:
            self.as_cb.set(asf.name)
        else:
            self.as_cb.set('')
        adv = self.model.adversaries.get(t.adversary_id)
        if adv:
            self.adv_cb.set(adv.name)
        else:
            self.adv_cb.set('')
        self.desc_txt.delete('1.0', 'end'); self.desc_txt.insert('1.0', t.description)
        self.lik_spin.set(t.likelihood)
        # ensure combos include the current values
        self.refresh_comboboxes()
        self.mit_combo.set(t.mitigation)
        self.val_combo.set(t.mitigation_validation)
        self.selected_threat_id = t.id

# ---------------- Threats Table (live filter & sorting & CSV) ----------------
class ThreatsTable(tk.Frame):
    def __init__(self, master, model: DataModel, on_edit_cb, on_delete_cb):
        super().__init__(master)
        self.model = model
        self.on_edit_cb = on_edit_cb
        self.on_delete_cb = on_delete_cb
        self.sort_by = None
        self.sort_reverse = False

        # Filter controls (live)
        filter_frame = ttk.Frame(self)
        ttk.Label(filter_frame, text='Filter:').pack(side='left', padx=(0,4))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=40)
        self.filter_entry.pack(side='left', fill='x', expand=True)
        # placeholder behavior
        self._placeholder = "🔍 Filter threats (type keywords, space-separated)"
        self._has_placeholder = False
        self._set_placeholder()
        self.filter_entry.bind('<FocusIn>', lambda e: self._clear_placeholder())
        self.filter_entry.bind('<FocusOut>', lambda e: self._set_placeholder())
        # live filtering
        self.filter_var.trace_add('write', lambda *args: self.refresh())
        ttk.Button(filter_frame, text='Clear', command=self._clear_filter_button).pack(side='left', padx=6)
        filter_frame.pack(fill='x', pady=3)

        # Columns: include separate asset_value column
        cols = (
            'asset', 'asset_value', 'attack_surface', 'adversary',
            'threat', 'likelihood', 'risk', 'severity', 'mitigation', 'validation'
        )
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=14)

        headings = [
            'Asset', 'Asset Value', 'Attack Surface', 'Adversary',
            'Threat', 'Likelihood', 'Risk', 'Severity', 'Mitigation', 'Validation'
        ]
        # attach sorting to headings (capture column in lambda default arg)
        for c, h in zip(cols, headings):
            self.tree.heading(c, text=h, command=(lambda col=c: lambda: self.sort_column(col))())
            self.tree.column(c, width=140, anchor='w')

        self.tree.pack(fill='both', expand=True)

        # Color tags for severity (may be ignored on some platforms)
        try:
            self.tree.tag_configure('Low', background='#e8ffe8')
            self.tree.tag_configure('Medium', background='#fff8d6')
            self.tree.tag_configure('High', background='#ffe9d0')
            self.tree.tag_configure('Critical', background='#ffd6d6')
        except Exception:
            pass

        # Buttons
        btns = ttk.Frame(self)
        ttk.Button(btns, text='Edit Selected', command=self.edit_selected).pack(side='left', padx=3)
        ttk.Button(btns, text='Delete Selected', command=self.delete_selected).pack(side='left', padx=3)
        ttk.Button(btns, text='Export CSV', command=self.export_csv).pack(side='left', padx=3)
        btns.pack(anchor='e', pady=6)

        self.refresh()

    # placeholder helpers
    def _set_placeholder(self):
        if not self.filter_var.get():
            self.filter_entry.delete(0, 'end')
            self.filter_entry.insert(0, self._placeholder)
            self.filter_entry.configure(foreground='gray')
            self._has_placeholder = True

    def _clear_placeholder(self):
        if self._has_placeholder:
            self.filter_entry.delete(0, 'end')
            self.filter_entry.configure(foreground='black')
            self._has_placeholder = False

    def _clear_filter_button(self):
        self.filter_var.set('')
        self._set_placeholder()

    def clear_filter(self):
        self._clear_filter_button()
        self.refresh()

    def sort_column(self, col):
        # toggles reverse if same column clicked twice
        self.sort_reverse = (self.sort_by == col and not self.sort_reverse)
        self.sort_by = col
        self.refresh()

    def refresh(self):
        # get search keywords (if placeholder is present, treat as empty)
        raw = self.filter_var.get()
        if self._has_placeholder:
            raw = ''
        search = raw.lower().strip()
        keywords = [k for k in search.split() if k]

        threats = list(self.model.threats.values())

        def sort_key(t: Threat):
            if not self.sort_by:
                return 0
            if self.sort_by == 'risk':
                return t.calculate_risk(self.model)
            if self.sort_by == 'asset_value':
                a = self.model.assets.get(t.asset_id)
                return a.value if a else 0
            if self.sort_by == 'likelihood':
                return t.likelihood
            if self.sort_by == 'asset':
                a = self.model.assets.get(t.asset_id)
                return a.name.lower() if a else ''
            if self.sort_by == 'attack_surface':
                asf = self.model.attack_surfaces.get(t.attack_surface_id)
                return asf.name.lower() if asf else ''
            if self.sort_by == 'adversary':
                adv = self.model.adversaries.get(t.adversary_id)
                return adv.name.lower() if adv else ''
            if self.sort_by == 'severity':
                # map severity to rank
                sev = t.risk_severity(self.model)
                order = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
                return order.get(sev, 0)
            # fallback textual attribute on threat
            return str(getattr(t, self.sort_by, '')).lower()

        if self.sort_by:
            threats.sort(key=sort_key, reverse=self.sort_reverse)

        # clear tree
        for r in self.tree.get_children():
            self.tree.delete(r)

        for t in threats:
            a = self.model.assets.get(t.asset_id)
            asf = self.model.attack_surfaces.get(t.attack_surface_id)
            adv = self.model.adversaries.get(t.adversary_id)
            risk = t.calculate_risk(self.model)
            severity = t.risk_severity(self.model)
            row = (
                a.name if a else '<missing asset>',
                a.value if a else '',
                asf.name if asf else '<missing as>',
                adv.name if adv else '<missing adv>',
                t.description,
                t.likelihood,
                risk,
                severity,
                t.mitigation,
                t.mitigation_validation,
            )
            # multi-keyword filter: each keyword must appear somewhere in the row's combined text
            if keywords:
                hay = ' '.join(map(str, row)).lower()
                if any(k not in hay for k in keywords):
                    continue
            self.tree.insert('', 'end', iid=t.id, values=row, tags=(severity,))

    def edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select a threat to edit')
            return
        self.on_edit_cb(sel[0])

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select a threat to delete')
            return
        if messagebox.askyesno('Confirm', 'Delete selected threat?'):
            self.on_delete_cb(sel[0])

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Asset', 'Asset Value', 'Attack Surface', 'Adversary',
                    'Threat', 'Likelihood', 'Risk', 'Severity', 'Mitigation', 'Validation'
                ])
                for t in self.model.threats.values():
                    a = self.model.assets.get(t.asset_id)
                    asf = self.model.attack_surfaces.get(t.attack_surface_id)
                    adv = self.model.adversaries.get(t.adversary_id)
                    writer.writerow([
                        a.name if a else '',
                        a.value if a else '',
                        asf.name if asf else '',
                        adv.name if adv else '',
                        t.description,
                        t.likelihood,
                        t.calculate_risk(self.model),
                        t.risk_severity(self.model),
                        t.mitigation,
                        t.mitigation_validation,
                    ])
            messagebox.showinfo('Exported', f'Threats exported to {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Could not export: {e}')

# ---------------- Threat Matrix window ----------------
class MatrixWindow(tk.Toplevel):
    def __init__(self, master, model: DataModel):
        super().__init__(master)
        self.title('Threat Matrix (Risk)')
        self.model = model
        self.geometry('1000x700')  # slightly taller to accommodate both sections

        if not MATPLOTLIB_AVAILABLE:
            ttk.Label(self, text='Matplotlib & numpy are required for matrix. Install: pip install matplotlib numpy').pack(padx=8, pady=8)
            return

        assets = list(model.assets.values())
        attack_surfaces = list(model.attack_surfaces.values())
        if not assets or not attack_surfaces:
            ttk.Label(self, text='Need assets and attack surfaces to build matrix').pack()
            return

        aset_idx = {a.id: i for i, a in enumerate(assets)}
        asurf_idx = {a.id: j for j, a in enumerate(attack_surfaces)}

        import numpy as np
        mat = np.zeros((len(assets), len(attack_surfaces)), dtype=float)
        cells = [[[] for _ in attack_surfaces] for _ in assets]
        for t in model.threats.values():
            ai = aset_idx.get(t.asset_id)
            aj = asurf_idx.get(t.attack_surface_id)
            if ai is None or aj is None:
                continue
            mat[ai, aj] += t.calculate_risk(model)
            cells[ai][aj].append(t)

        # Build the top figure
        fig = Figure(figsize=(9, 5))
        ax = fig.add_subplot(111)
        cax = ax.matshow(mat, cmap='Reds')
        fig.colorbar(cax, ax=ax)
        ax.set_xticks(range(len(attack_surfaces)))
        ax.set_xticklabels([a.name for a in attack_surfaces], rotation=45, ha='right')
        ax.set_yticks(range(len(assets)))
        ax.set_yticklabels([f"{a.name} (v{a.value})" for a in assets])
        ax.set_title('Risk Matrix (sum of asset.value × likelihood)', pad=20)

        # Adjust margins so labels & title are visible
        fig.subplots_adjust(left=0.25, right=0.95, top=0.85, bottom=0.25)

        # Paned layout to keep both chart and list visible
        paned = ttk.PanedWindow(self, orient='vertical')
        paned.pack(fill='both', expand=True)

        # top: chart
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)

        canvas = FigureCanvasTkAgg(fig, master=top_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill='both', expand=True, padx=4, pady=4)

        # bottom: list of selected threats
        bottom_frame = ttk.Frame(paned)
        paned.add(bottom_frame, weight=1)

        ttk.Label(bottom_frame, text='Selected cell threats:').pack(anchor='w', padx=6, pady=(4, 2))
        self.listbox = tk.Listbox(bottom_frame, height=6)
        self.listbox.pack(fill='both', expand=True, padx=6, pady=(0, 6))

        def on_click(event):
            try:
                inv = ax.transData.inverted()
                xdata, ydata = inv.transform((event.x, event.y))
                col = int(round(xdata))
                row = int(round(ydata))
            except Exception:
                return
            self.listbox.delete(0, 'end')
            if 0 <= row < mat.shape[0] and 0 <= col < mat.shape[1]:
                for t in cells[row][col]:
                    adv = model.adversaries.get(t.adversary_id)
                    label = f"[{t.likelihood}] {adv.name if adv else '??'} -> {t.description[:120]}"
                    self.listbox.insert('end', label)

        canvas.mpl_connect('button_press_event', on_click)


# ---------------- Supporting dialogs ----------------
class AssetDialog(tk.Toplevel):
    def __init__(self, master, title='Asset', name='', value='3'):
        super().__init__(master)
        self.title(title)
        self.result = None
        ttk.Label(self, text='Name:').grid(row=0, column=0, pady=4, padx=4)
        self.name_entry = ttk.Entry(self); self.name_entry.grid(row=0, column=1, pady=4, padx=4)
        self.name_entry.insert(0, name)
        ttk.Label(self, text='Value (1-5):').grid(row=1, column=0, pady=4, padx=4)
        self.value_spin = ttk.Spinbox(self, from_=1, to=5, width=6)
        self.value_spin.grid(row=1, column=1, pady=4, padx=4)
        self.value_spin.set(value)
        btnf = ttk.Frame(self)
        ttk.Button(btnf, text='OK', command=self.on_ok).pack(side='left', padx=6)
        ttk.Button(btnf, text='Cancel', command=self.destroy).pack(side='left', padx=6)
        btnf.grid(row=2, column=1, pady=6)
        self.grab_set(); self.name_entry.focus_set()

    def on_ok(self):
        name = self.name_entry.get().strip()
        val = self.value_spin.get()
        if not name:
            messagebox.showerror('Missing', 'Enter a name'); return
        try:
            ival = int(val)
            if ival < 1 or ival > 5:
                raise ValueError()
        except Exception:
            messagebox.showerror('Bad value', 'Value must be integer 1..5'); return
        self.result = {'name': name, 'value': ival}
        self.destroy()

# ---------------- Main application ----------------
class ThreatModelerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Threat Modeler')
        self.geometry('1200x760')
        self.model = DataModel()
        self._populate_sample()

        # menu
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label='Export (JSON)...', command=self.export_json)
        filem.add_command(label='Import (JSON)...', command=self.import_json)
        filem.add_separator()
        filem.add_command(label='Exit', command=self.quit)
        menubar.add_cascade(label='File', menu=filem)
        menubar.add_command(label='Threat Matrix', command=self.open_matrix)
        self.config(menu=menubar)

        # left editors
        left = ttk.Frame(self)
        left.pack(side='left', fill='y', padx=6, pady=6)

        self.asset_editor = ListEditor(left, 'Assets (name, value)', ['name', 'value'],
                                       get_items_cb=lambda: list(self.model.assets.values()),
                                       add_cb=self.add_asset, edit_cb=self.edit_asset, delete_cb=self.delete_asset)
        self.asset_editor.pack(fill='x', pady=4)

        self.as_editor = ListEditor(left, 'Attack Surfaces (name)', ['name'],
                                    get_items_cb=lambda: list(self.model.attack_surfaces.values()),
                                    add_cb=self.add_attack_surface, edit_cb=self.edit_attack_surface, delete_cb=self.delete_attack_surface)
        self.as_editor.pack(fill='x', pady=4)

        self.adv_editor = ListEditor(left, 'Adversaries (name)', ['name'],
                                     get_items_cb=lambda: list(self.model.adversaries.values()),
                                     add_cb=self.add_adversary, edit_cb=self.edit_adversary, delete_cb=self.delete_adversary)
        self.adv_editor.pack(fill='x', pady=4)

        # right side: threat editor + table
        right = ttk.Frame(self)
        right.pack(side='left', fill='both', expand=True, padx=6, pady=6)

        self.threat_editor = ThreatEditor(right, self.model, on_change_cb=self.on_model_changed)
        self.threat_editor.pack(fill='x')

        self.threats_table = ThreatsTable(right, self.model, on_edit_cb=self.on_edit_threat, on_delete_cb=self.on_delete_threat)
        self.threats_table.pack(fill='both', expand=True, pady=6)

        self.refresh_all()

    def _populate_sample(self):
        # small sample
        a1 = Asset(id=newid(), name='Customer DB', value=5)
        a2 = Asset(id=newid(), name='Web App', value=4)
        self.model.assets[a1.id] = a1
        self.model.assets[a2.id] = a2
        as1 = AttackSurface(id=newid(), name='Public API')
        as2 = AttackSurface(id=newid(), name='Admin Interface')
        self.model.attack_surfaces[as1.id] = as1
        self.model.attack_surfaces[as2.id] = as2
        adv1 = Adversary(id=newid(), name='External Attacker')
        adv2 = Adversary(id=newid(), name='Malicious Insider')
        self.model.adversaries[adv1.id] = adv1
        self.model.adversaries[adv2.id] = adv2

    # ---- Asset CRUD ----
    def add_asset(self):
        d = AssetDialog(self, title='Add Asset')
        self.wait_window(d)
        if d.result:
            aid = newid()
            self.model.assets[aid] = Asset(id=aid, name=d.result['name'], value=int(d.result['value']))
            self.refresh_all()

    def edit_asset(self, aid):
        a = self.model.assets.get(aid)
        if not a: return
        d = AssetDialog(self, title='Edit Asset', name=a.name, value=str(a.value))
        self.wait_window(d)
        if d.result:
            a.name = d.result['name']
            a.value = int(d.result['value'])
            self.refresh_all()

    def delete_asset(self, aid):
        if aid in self.model.assets:
            del self.model.assets[aid]
        self.refresh_all()

    # ---- Attack surface CRUD ----
    def add_attack_surface(self):
        name = simpledialog.askstring('Add Attack Surface', 'Name:')
        if name:
            aid = newid(); self.model.attack_surfaces[aid] = AttackSurface(id=aid, name=name)
            self.refresh_all()

    def edit_attack_surface(self, aid):
        a = self.model.attack_surfaces.get(aid)
        if not a: return
        name = simpledialog.askstring('Edit Attack Surface', 'Name:', initialvalue=a.name)
        if name:
            a.name = name; self.refresh_all()

    def delete_attack_surface(self, aid):
        if aid in self.model.attack_surfaces:
            del self.model.attack_surfaces[aid]
        self.refresh_all()

    # ---- Adversary CRUD ----
    def add_adversary(self):
        name = simpledialog.askstring('Add Adversary', 'Name:')
        if name:
            aid = newid(); self.model.adversaries[aid] = Adversary(id=aid, name=name); self.refresh_all()

    def edit_adversary(self, aid):
        a = self.model.adversaries.get(aid)
        if not a: return
        name = simpledialog.askstring('Edit Adversary', 'Name:', initialvalue=a.name)
        if name:
            a.name = name; self.refresh_all()

    def delete_adversary(self, aid):
        if aid in self.model.adversaries:
            del self.model.adversaries[aid]
        self.refresh_all()

    # ---- Threat callbacks ----
    def on_model_changed(self):
        # called when threats added/edited and when lists change
        self.refresh_all()

    def on_edit_threat(self, tid):
        # open the threat editor for a threat id
        # make sure the editor comboboxes are refreshed first
        self.threat_editor.refresh_comboboxes()
        self.threat_editor.edit_threat(tid)

    def on_delete_threat(self, tid):
        if tid in self.model.threats:
            del self.model.threats[tid]
        self.refresh_all()

    def refresh_all(self):
        # refresh editors and table; ensures name updates propagate
        self.asset_editor.refresh()
        self.as_editor.refresh()
        self.adv_editor.refresh()
        self.threat_editor.refresh_comboboxes()
        self.threats_table.refresh()

    # ---- Import/Export JSON ----
    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')])
        if not path: return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.model.to_json())
            messagebox.showinfo('Exported', f'Exported to {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Could not save: {e}')

    def import_json(self):
        path = filedialog.askopenfilename(filetypes=[('JSON', '*.json')])
        if not path: return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                s = f.read()
            self.model = DataModel.from_json(s)
            # rewire UI references
            self.threat_editor.model = self.model
            self.threats_table.model = self.model
            self.threat_editor.on_change_cb = self.on_model_changed
            self.threats_table.on_edit_cb = self.on_edit_threat
            self.threats_table.on_delete_cb = self.on_delete_threat
            self.refresh_all()
            messagebox.showinfo('Imported', f'Imported from {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Could not import: {e}')

    # ---- Matrix ----
    def open_matrix(self):
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showwarning('Missing matplotlib', 'Matplotlib & numpy are required for threat matrix view. Install via: pip install matplotlib numpy')
            return
        MatrixWindow(self, self.model)

# ---------------- Run ----------------
if __name__ == '__main__':
    app = ThreatModelerApp()
    app.mainloop()

