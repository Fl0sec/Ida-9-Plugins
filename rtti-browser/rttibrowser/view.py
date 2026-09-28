"""IDA-native linked choosers for cached RTTI classes and live methods."""

import ida_kernwin

from .presentation import compact, hierarchy_summary, is_compiler_generated


CHD_MULTINH = 0x01
CHD_VIRTINH = 0x02
CHD_AMBIGUOUS = 0x04


def _inheritance_flags(attributes):
    flags = []
    if attributes & CHD_MULTINH:
        flags.append("MI")
    if attributes & CHD_VIRTINH:
        flags.append("VI")
    if attributes & CHD_AMBIGUOUS:
        flags.append("A")
    return "/".join(flags) if flags else "SI"


class ClassChooser(ida_kernwin.Choose):
    """Searchable class/subobject list backed by one validated snapshot."""

    TITLE = "RTTI Classes"

    def __init__(self, controller, records):
        flags = (
            ida_kernwin.Choose.CH_RESTORE
            | ida_kernwin.Choose.CH_QFLT
            | ida_kernwin.Choose.CH_QFTYP_FUZZY
        )
        ida_kernwin.Choose.__init__(
            self,
            self.TITLE,
            [
                ["Class", 36],
                ["Subobject", 30],
                ["Offset", 8 | ida_kernwin.Choose.CHCOL_HEX],
                ["Methods", 7 | ida_kernwin.Choose.CHCOL_DEC],
                ["Kind", 8],
                ["Vtable", 16 | ida_kernwin.Choose.CHCOL_EA],
                ["Hierarchy", 80],
            ],
            flags=flags,
        )
        self.controller = controller
        self.all_records = list(records)
        self.show_all = False
        self.records = []
        self.rows = []
        self._rebuild()
        self.cmd_methods = self.AddCommand(
            "Show virtual methods", shortcut="Ctrl+Enter"
        )
        self.cmd_vtable = self.AddCommand("Jump to owning vtable")
        self.cmd_col = self.AddCommand("Jump to complete object locator")
        self.cmd_details = self.AddCommand("Show full RTTI details")
        self.cmd_show_all = self.AddCommand("Show all RTTI")
        self.cmd_show_relevant = self.AddCommand("Show relevant classes")
        self.cmd_all_methods = self.AddCommand(
            "Open global virtual methods", shortcut="Ctrl+M"
        )
        self.cmd_rescan = self.AddCommand("Rescan RTTI", shortcut="Ctrl+R")
        self.cmd_info = self.AddCommand("Snapshot information")

    def OnGetSize(self):
        return len(self.records)

    def OnGetLine(self, n):
        return self.rows[n]

    def OnGetEA(self, n):
        return self.controller.ea(self.records[n].vtable_rva)

    def OnSelectLine(self, n):
        if 0 <= n < len(self.records):
            self.controller.show_methods(self.records[n])
        return [ida_kernwin.Choose.NOTHING_CHANGED, n]

    def OnCommand(self, n, cmd_id):
        if not 0 <= n < len(self.records):
            return 1
        record = self.records[n]
        if cmd_id == self.cmd_methods:
            self.controller.show_methods(record)
        elif cmd_id == self.cmd_vtable:
            ida_kernwin.jumpto(self.controller.ea(record.vtable_rva))
        elif cmd_id == self.cmd_col:
            ida_kernwin.jumpto(self.controller.ea(record.col_rva))
        elif cmd_id == self.cmd_details:
            self._show_details(record)
        elif cmd_id == self.cmd_show_all:
            self._set_mode(True)
        elif cmd_id == self.cmd_show_relevant:
            self._set_mode(False)
        elif cmd_id == self.cmd_all_methods:
            self.controller.show_global_methods()
        elif cmd_id == self.cmd_rescan:
            self.controller.rescan()
        elif cmd_id == self.cmd_info:
            self.controller.show_snapshot_info()
        return 1

    def _rebuild(self):
        records = self.all_records
        if not self.show_all:
            relevant = [record for record in records
                        if not is_compiler_generated(record.class_name)]
            # An unusual binary containing only generated types is still
            # browsable; an empty default view would look like a failed scan.
            records = relevant or records
        self.records = records
        self.rows = [self._row(record) for record in records]

    def _row(self, record):
        subobject = "" if record.subobject == record.class_name else record.subobject
        return [
            compact(record.class_name, 96),
            compact(subobject, 72),
            "%X" % record.object_offset,
            str(record.method_count),
            _inheritance_flags(record.attributes),
            "%X" % self.controller.ea(record.vtable_rva),
            hierarchy_summary((base.name for base in record.bases)),
        ]

    def _set_mode(self, show_all):
        if self.show_all == show_all:
            return
        self.show_all = show_all
        self._rebuild()
        self.Refresh()

    def _show_details(self, record):
        hierarchy = "\n  ".join(base.name for base in record.bases)
        ida_kernwin.info(
            "Class: %s\n"
            "Subobject: %s\n"
            "Object offset: 0x%X\n"
            "Methods: %d\n"
            "Inheritance: %s\n"
            "Vtable: 0x%X\n"
            "Complete object locator: 0x%X\n\n"
            "Hierarchy:\n  %s"
            % (
                record.class_name, record.subobject, record.object_offset,
                record.method_count, _inheritance_flags(record.attributes),
                self.controller.ea(record.vtable_rva),
                self.controller.ea(record.col_rva), hierarchy,
            )
        )

    def OnClose(self):
        self.controller.closed(self)


class MethodChooser(ida_kernwin.Choose):
    """One class's methods or a lazily built global ownership index."""

    def __init__(self, controller, title, rows):
        flags = (
            ida_kernwin.Choose.CH_RESTORE
            | ida_kernwin.Choose.CH_QFLT
            | ida_kernwin.Choose.CH_QFTYP_FUZZY
        )
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Slot", 6 | ida_kernwin.Choose.CHCOL_DEC],
                ["Offset", 8 | ida_kernwin.Choose.CHCOL_HEX],
                ["Entry", 16 | ida_kernwin.Choose.CHCOL_EA],
                ["Target", 16 | ida_kernwin.Choose.CHCOL_EA],
                ["Function", 45 | ida_kernwin.Choose.CHCOL_FNAME],
                ["Owner", 45],
            ],
            flags=flags,
        )
        self.controller = controller
        self.rows = rows
        self.lines = [self._line(row) for row in rows]
        self.cmd_target = self.AddCommand("Jump to virtual method")
        self.cmd_entry = self.AddCommand("Jump to vtable slot entry")
        self.cmd_vtable = self.AddCommand("Jump to owning vtable")

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.lines[n]

    @staticmethod
    def _line(row):
        return [
            str(row["slot"]),
            "%X" % row["offset"],
            "%X" % row["entry_ea"],
            "%X" % row["target_ea"],
            compact(row["name"], 120),
            compact(row["owner"], 120),
        ]

    def OnGetEA(self, n):
        return self.rows[n]["target_ea"]

    def OnSelectLine(self, n):
        if 0 <= n < len(self.rows):
            ida_kernwin.jumpto(self.rows[n]["target_ea"])
        return [ida_kernwin.Choose.NOTHING_CHANGED, n]

    def OnCommand(self, n, cmd_id):
        if not 0 <= n < len(self.rows):
            return 1
        row = self.rows[n]
        if cmd_id == self.cmd_target:
            ida_kernwin.jumpto(row["target_ea"])
        elif cmd_id == self.cmd_entry:
            ida_kernwin.jumpto(row["entry_ea"])
        elif cmd_id == self.cmd_vtable:
            ida_kernwin.jumpto(row["vtable_ea"])
        return 1

    def OnClose(self):
        self.controller.closed(self)
