# Plugin anatomy

The canonical shape of an IDA 9.0 Python plugin in this repo. A runnable copy
of everything here is in [`templates/plugin_skeleton/`](../templates/plugin_skeleton/).

## The entry file, top to bottom

### 1. Header comment

What the plugin does, where the logic lives, and the target line
(`Target: IDA Professional 9.0 / Python 3.12.`).

### 2. The sys.path + reload shim — always first, above all other imports

```python
import os
import sys

# Make the sibling `myplugin` package importable regardless of IDA's sys.path,
# and force a fresh import on every (re)load so edits take effect.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [n for n in list(sys.modules)
                 if n == "myplugin" or n.startswith("myplugin.")]:
    del sys.modules[_modname]
```

Why both halves matter:

- IDA does not put the plugins directory on `sys.path`, so `import myplugin`
  fails without the first half.
- Python caches modules for the life of the process. Without the purge, editing
  the package and reloading the plugin runs the **old** code — you debug a file
  IDA is not executing. This costs hours; keep the shim.

### 3. Imports

stdlib, blank line, IDA modules, blank line, local package. Specific modules
only.

### 4. Module constants

Plugin name, action ids (namespaced: `"myplugin:do_thing"`), hotkeys, tuning
constants. Action ids and hotkeys are the plugin's identity — stable.

### 5. Logic / orchestration

Only what is specific to this entry point. Reusable machinery belongs in the
package.

### 6. Action handlers

```python
class DoThingHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ...
        return 1            # 1 = handled, IDB may have changed

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)
```

`update` decides where the action is live. The usual helper:

```python
def _enable_for(ctx, widget_type):
    # `getattr`, not `ctx.widget_type` -- the attribute is absent in some
    # action contexts and an AttributeError here breaks the whole popup.
    if getattr(ctx, "widget_type", None) == widget_type:
        return ida_kernwin.AST_ENABLE_FOR_WIDGET
    return ida_kernwin.AST_DISABLE_FOR_WIDGET
```

### 7. UI hooks — context menus

```python
class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_FUNCS:
            for aid in (ACTION_A, ACTION_B):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid,
                                                   "MyPlugin/")
```

The trailing `"MyPlugin/"` groups the entries into a submenu. Use one for
anything beyond a single action.

### 8. The action table

Declare actions once, as data, and drive both registration and teardown from it:

```python
# (action_id, label, handler_factory, hotkey, tooltip)
_ACTIONS = [
    (ACTION_A, "Do the thing", DoThingHandler, "Ctrl+Shift+E", "Tooltip text"),
]
```

This is the pattern that keeps `init()`/`term()` symmetric — a registered
action with no matching unregister leaks across plugin reloads and IDA will
refuse to re-register the id.

### 9. `plugin_t` and `PLUGIN_ENTRY`

```python
class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "One-line description"
    help = "Longer help shown by IDA"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.handlers = []                  # keep refs; IDA does not own them
        self.hooks = Hooks()
        for action_id, label, factory, hotkey, tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)   # tolerate a reload
            handler = factory()
            self.handlers.append(handler)
            if not ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action_id, label, handler, hotkey, tip, -1)
            ):
                msg("Action registration failed: %s" % action_id)
                return idaapi.PLUGIN_SKIP
        self.hooks.hook()
        msg("%s initialized." % VERSION)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info("Functions window -> right-click -> MyPlugin.")

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        for action_id, _l, _f, _h, _t in _ACTIONS:
            ida_kernwin.unregister_action(action_id)


def PLUGIN_ENTRY():
    return MyPlugin()
```

Three things that are easy to get wrong:

- **Keep a reference to every handler** (`self.handlers`). IDA stores a raw
  pointer; if Python garbage-collects the handler, activating the action
  crashes IDA.
- **`unregister_action` before registering.** Re-registering an existing id
  fails, so without this a plugin reload leaves you with dead actions.
- **`PLUGIN_KEEP`** keeps the plugin resident so hooks and actions stay alive.
  `PLUGIN_SKIP` unloads it. `PLUGIN_HIDE` keeps it out of the Edit→Plugins
  menu, which is right when the UI is context menus and hotkeys.

## Flags

| Flag | Meaning |
|---|---|
| `PLUGIN_PROC` | load when a processor module is loaded (i.e. per-IDB) — the usual choice |
| `PLUGIN_HIDE` | don't list in Edit→Plugins |
| `PLUGIN_FIX` | load at IDA startup, stay for the session |
| `PLUGIN_MOD` | the plugin modifies the database |
| `PLUGIN_UNL` | unload after `run()` — for one-shot script-like plugins |
| `PLUGIN_MULTI` | `init()` returns a `plugmod_t` instead of a status (per-IDB instance) |

Return from `init()`: `PLUGIN_KEEP` (stay resident), `PLUGIN_OK` (load, unload
after run), `PLUGIN_SKIP` (don't load).

## Long-running work must be cancellable

```python
ida_kernwin.show_wait_box("Processing...")
try:
    for i, item in enumerate(items):
        if i % PROGRESS_EVERY == 0:
            if ida_kernwin.user_cancelled():
                msg("Cancelled by user at %d/%d." % (i, len(items)))
                break
            ida_kernwin.replace_wait_box("Processing %d/%d..." % (i, len(items)))
        try:
            process(item)
        except Exception as exc:
            msg("item %s failed: %s" % (item, exc))   # never abort the batch
finally:
    ida_kernwin.hide_wait_box()
```

`hide_wait_box` in a `finally` is mandatory — an escaped exception otherwise
leaves IDA with a modal wait box and no way out but a restart.

## Reporting results

Two channels, both used:

- `msg()` — a prefixed line per item to the Output window. This is the debug
  log; there is no other one.
- A final `ida_kernwin.info(...)` popup with the summary counts, so the user
  gets an answer without reading the Output window.

## Optional: `ida-plugin.json`

IDA 9 reads a plugin manifest when present. Worth adding for anything shared:

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "My Plugin",
    "entryPoint": "my-plugin.py",
    "idaVersions": ">=9.0",
    "version": "1.0.0",
    "description": "One line.",
    "categories": ["api-scripting-and-automation"]
  }
}
```
