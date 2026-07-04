import ast
from dataclasses import dataclass, field
from typing import List

# Not a sandbox — a static gate. Blocks the obvious ways generated code could
# reach outside the plugin contract (filesystem/process/import-time tricks),
# on top of the mandatory quarantine + manual review step in PluginManager/CLI.
DENYLIST_IMPORTS = {"os", "subprocess", "sys", "shutil", "importlib", "ctypes", "pickle"}
DENYLIST_CALLS = {"eval", "exec", "__import__", "compile"}


@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)


def _inherits_scan_plugin(node: ast.ClassDef) -> bool:
    for base in node.bases:
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", None)
        if name == "ScanPlugin":
            return True
    return False


def validate(code: str) -> ValidationResult:
    errors: List[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return ValidationResult(False, [f"syntax error: {e}"])

    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    if not any(_inherits_scan_plugin(c) for c in classes):
        errors.append("no class inherits ScanPlugin")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".")[0] for alias in node.names}
            bad = names & DENYLIST_IMPORTS
            if bad:
                errors.append(f"disallowed import(s): {sorted(bad)}")
        elif isinstance(node, ast.ImportFrom):
            module_root = (node.module or "").split(".")[0]
            if module_root in DENYLIST_IMPORTS:
                errors.append(f"disallowed import: {module_root}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in DENYLIST_CALLS:
            errors.append(f"disallowed call: {node.func.id}(...)")
        elif isinstance(node, ast.FunctionDef) and node.name == "__init__":
            errors.append("plugins must not define __init__")

    required_methods = {"should_run", "run"}
    defined_methods = {n.name for c in classes for n in c.body if isinstance(n, ast.FunctionDef)}
    missing = required_methods - defined_methods
    if missing:
        errors.append(f"missing required method(s): {sorted(missing)}")

    return ValidationResult(ok=not errors, errors=errors)
