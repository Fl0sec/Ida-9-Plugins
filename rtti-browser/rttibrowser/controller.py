"""RTTI scan/cache lifecycle and chooser orchestration."""

import time

import ida_kernwin
import ida_nalt

from .common import ScanCancelled, msg
from .model import method_sort_key
from .presentation import compact
from .scanner import RttiScanner
from . import store
from .view import ClassChooser, MethodChooser


class RttiController:
    """Own the active snapshot and every non-modal chooser reference."""

    def __init__(self):
        self.snapshot = None
        self.windows = []

    @staticmethod
    def ea(rva):
        return int(ida_nalt.get_imagebase()) + int(rva)

    @staticmethod
    def _cancelled():
        return bool(ida_kernwin.user_cancelled())

    @staticmethod
    def _progress(stage, current, total):
        if total:
            ida_kernwin.replace_wait_box(
                "%s: %d/%d..." % (stage, current, total)
            )
        else:
            ida_kernwin.replace_wait_box("%s..." % stage)

    def open(self):
        identity = store.current_identity()
        snapshot = self.snapshot
        source = "session cache"
        if snapshot is None or snapshot.identity != identity:
            snapshot, reason = store.load(identity)
            source = "IDB cache"
            if snapshot is None:
                msg("CACHE: %s; scanning" % reason)
                self.scan(confirm=False)
                return

        valid = self._validate_snapshot(snapshot)
        if valid is None:
            return
        if not valid:
            self.scan(confirm=False)
            return
        self.snapshot = snapshot
        msg("CACHE: opened %d vtable(s) from %s"
            % (len(snapshot.records), source))
        self.show_classes()

    def _validate_snapshot(self, snapshot):
        scanner = RttiScanner(cancelled=self._cancelled, progress=self._progress)
        ida_kernwin.show_wait_box("Validating cached RTTI...")
        try:
            total = len(snapshot.records)
            for index, record in enumerate(snapshot.records):
                if index % 64 == 0:
                    if self._cancelled():
                        raise ScanCancelled("cache validation cancelled")
                    self._progress("Validating cached RTTI", index, total)
                ok, reason = scanner.validate_anchor(record)
                if not ok:
                    msg("CACHE: %s is stale: %s" % (record.class_name, reason))
                    store.delete()
                    return False
            return True
        except ScanCancelled as exc:
            msg(str(exc))
            return None
        except Exception as exc:
            msg("CACHE: validation failed: %s" % exc)
            store.delete()
            return False
        finally:
            ida_kernwin.hide_wait_box()

    def scan(self, confirm=True):
        if confirm and ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Rescan all verified MSVC RTTI?\n\n"
            "The current cache remains usable if the scan is cancelled.",
        ) != ida_kernwin.ASKBTN_YES:
            return

        before = store.current_identity()
        started = time.monotonic()
        scanner = RttiScanner(cancelled=self._cancelled, progress=self._progress)
        ida_kernwin.show_wait_box("Scanning verified MSVC RTTI...")
        try:
            snapshot = scanner.scan(before, deep_scan=True)
            after = store.current_identity()
            if before != after:
                raise RuntimeError("image identity or layout changed during scan")
        except ScanCancelled:
            msg("SCAN: cancelled; previous cache was not replaced")
            return
        except Exception as exc:
            msg("SCAN: failed; previous cache was not replaced: %s" % exc)
            ida_kernwin.warning("RTTI scan failed:\n\n%s" % exc)
            return
        finally:
            ida_kernwin.hide_wait_box()

        persisted, reason = store.save(snapshot)
        if not persisted:
            msg("CACHE: %s" % reason)
        self.snapshot = snapshot
        elapsed = time.monotonic() - started
        msg("SCAN: found %d validated vtable(s) in %.2fs"
            % (len(snapshot.records), elapsed))
        self.close_windows()
        self.show_classes()

    def rescan(self):
        self.scan(confirm=True)

    def show_classes(self):
        if self.snapshot is None:
            self.open()
            return
        chooser = ClassChooser(self, self.snapshot.records)
        self.windows.append(chooser)
        chooser.Show(False)

    def _method_rows(self, records, title):
        scanner = RttiScanner(cancelled=self._cancelled, progress=self._progress)
        rows = []
        total = sum(record.method_count for record in records)
        current = 0
        stale_reason = None
        ida_kernwin.show_wait_box("%s..." % title)
        try:
            for record in records:
                for slot in range(record.method_count):
                    if current % 128 == 0:
                        if self._cancelled():
                            raise ScanCancelled("method indexing cancelled")
                        self._progress(title, current, total)
                    try:
                        entry_ea, target_ea, name = scanner.method(record, slot)
                    except Exception as exc:
                        stale_reason = "%s slot %d failed validation: %s" % (
                            record.owner_label(), slot, exc,
                        )
                        break
                    rows.append({
                        "slot": slot,
                        "offset": slot * scanner.pointer_size,
                        "entry_ea": entry_ea,
                        "target_ea": target_ea,
                        "name": name,
                        "owner": record.owner_label(),
                        "object_offset": record.object_offset,
                        "vtable_ea": self.ea(record.vtable_rva),
                    })
                    current += 1
                if stale_reason:
                    break
        except ScanCancelled as exc:
            msg(str(exc))
            return None
        finally:
            ida_kernwin.hide_wait_box()
        if stale_reason:
            self._stale(stale_reason)
            return None
        return rows

    def show_methods(self, record):
        rows = self._method_rows([record], "Reading virtual methods")
        if rows is None:
            return
        title = "RTTI Methods: %s" % compact(record.owner_label(), 80)
        chooser = MethodChooser(self, title, rows)
        self.windows.append(chooser)
        chooser.Show(False)

    def show_global_methods(self):
        if self.snapshot is None:
            return
        rows = self._method_rows(
            self.snapshot.records, "Building virtual method index",
        )
        if rows is None:
            return
        rows.sort(key=method_sort_key)
        chooser = MethodChooser(self, "RTTI Virtual Methods", rows)
        self.windows.append(chooser)
        chooser.Show(False)

    def _stale(self, reason):
        msg("CACHE: stale snapshot: %s" % reason)
        store.delete()
        self.snapshot = None
        ida_kernwin.warning(
            "The RTTI snapshot no longer matches this IDB.\n\n"
            "%s\n\nRun RTTI Browser again to rescan." % reason
        )

    def show_snapshot_info(self):
        if self.snapshot is None:
            return
        method_count = sum(record.method_count for record in self.snapshot.records)
        ida_kernwin.info(
            "RTTI Browser snapshot\n\n"
            "validated vtables: %d\n"
            "virtual ownership rows: %d\n"
            "address storage: RVA (rebase-safe)\n"
            "method names: resolved live"
            % (len(self.snapshot.records), method_count)
        )

    def closed(self, chooser):
        try:
            self.windows.remove(chooser)
        except ValueError:
            pass

    def close_windows(self):
        for chooser in list(self.windows):
            try:
                chooser.Close()
            except Exception:
                pass
        self.windows = []
