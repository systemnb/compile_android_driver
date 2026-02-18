# .github/scripts/run_kadeflow.py
import os
import sys
import shlex
import yaml
import json
import subprocess
from pathlib import Path

def run(cmd: str, cwd: str | None = None):
    print(f"[run] {cmd}")
    subprocess.run(cmd, cwd=cwd, shell=True, check=True)

def deep_merge(a, b):
    if not isinstance(a, dict) or not isinstance(b, dict):
        return b
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))

def find_plugin_dir(plugin_name: str) -> Path:
    # 1) try lyenv plugin path
    try:
        out = subprocess.check_output(["bash", "-lc", f"lyenv plugin path {shlex.quote(plugin_name)}"], text=True).strip()
        p = Path(out).expanduser().resolve()
        if p.exists():
            return p
    except Exception:
        pass

    lyenv_home = os.environ.get("LYENV_HOME", "")
    if lyenv_home:
        # 2) common layout: $LYENV_HOME/plugins/<name>
        p = Path(lyenv_home).joinpath("plugins", plugin_name)
        if p.exists():
            return p.resolve()

        # 3) brute search for manifest.yaml containing plugin name
        root = Path(lyenv_home)
        for m in root.rglob("manifest.yaml"):
            try:
                txt = m.read_text(encoding="utf-8", errors="ignore")
                if f"name: {plugin_name}" in txt:
                    return m.parent.resolve()
            except Exception:
                continue

    raise RuntimeError(f"Cannot locate plugin directory for '{plugin_name}'")

def expand_env_in_obj(obj):
    """
    Recursively expand environment variables in strings like:
      ${GITHUB_WORKSPACE}, $GITHUB_WORKSPACE
    """
    import os

    if isinstance(obj, dict):
        return {k: expand_env_in_obj(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [expand_env_in_obj(x) for x in obj]

    if isinstance(obj, str):
        # Expand ${VAR} / $VAR and ~
        return os.path.expandvars(os.path.expanduser(obj))

    return obj


def write_plugin_config(plugin_dir: Path, overrides: dict):
    # Plugin reads ./config.yaml in its own dir
    cfg_path = plugin_dir / "config.yaml"

    base = {}
    if cfg_path.exists():
        base = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    merged = deep_merge(base, overrides)
    cfg_path.write_text(yaml.safe_dump(merged, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"[info] wrote plugin config: {cfg_path}")

def main():
    config_path = None
    if "--config" in sys.argv:
        i = sys.argv.index("--config")
        if i + 1 < len(sys.argv):
            config_path = Path(sys.argv[i + 1]).resolve()
    if not config_path or not config_path.exists():
        raise SystemExit("Missing --config <kadeflow.yaml>")

    flow = load_yaml(config_path)

    project_name = flow.get("project", {}).get("name", "ci-kade")
    plugin_name = flow.get("project", {}).get("plugin", "kade")
    plugin_source = flow.get("project", {}).get("plugin_source", "")

    # Install plugin
    if plugin_source:
        run(f"lyenv plugin install {shlex.quote(plugin_source)}")
    else:
        run(f"lyenv plugin install {shlex.quote(plugin_name)}")

    plugin_dir = find_plugin_dir(plugin_name)

    # Apply config overrides into plugin config.yaml
    overrides = flow.get("kade", {}).get("config_overrides", {}) or {}
    overrides = expand_env_in_obj(overrides)
    if overrides:
        write_plugin_config(plugin_dir, overrides)

    # Execute default steps
    steps = flow.get("flow", {}).get("steps", []) or []

    # ABI injection:
    abi = flow.get("abi", {}) or {}
    upstream_patch = bool(abi.get("upstream_patch", True))

    # Ensure abi_upstream is present if enabled
    if upstream_patch and not any(s.strip().startswith("kade abi_upstream") for s in steps):
        # Insert before build if possible, else append
        inserted = False
        for idx, s in enumerate(steps):
            if s.strip().startswith("kade build"):
                steps.insert(idx, "kade abi_upstream")
                inserted = True
                break
        if not inserted:
            steps.append("kade abi_upstream")

    # Insert abi symbol export if provided
    abi_cmd = ""
    symbols_file = abi.get("symbols_file", "")
    symbols = abi.get("symbols", [])
    do_sort = bool(abi.get("sort", False))
    do_replace = bool(abi.get("replace", False))

    if symbols_file:
        symfile = os.path.expandvars(str(symbols_file))
        abi_cmd = f"kade abi {'--replace ' if do_replace else ''}{'--sort ' if do_sort else ''}--file {shlex.quote(symfile)}"
    elif isinstance(symbols, list) and symbols:
        sym_args = " ".join(shlex.quote(str(x)) for x in symbols)
        abi_cmd = f"kade abi {'--replace ' if do_replace else ''}{'--sort ' if do_sort else ''}{sym_args}"

    if abi_cmd:
        # Insert before build if possible
        inserted = False
        for idx, s in enumerate(steps):
            if s.strip().startswith("kade build"):
                steps.insert(idx, abi_cmd)
                inserted = True
                break
        if not inserted:
            steps.append(abi_cmd)

    # Run steps (activation already done in workflow step)
    for cmd in steps:
        cmd = os.path.expandvars(cmd)
        run(cmd)

    # Post commands
    post_cmds = flow.get("flow", {}).get("post_commands", []) or []
    for cmd in post_cmds:
        cmd = os.path.expandvars(cmd)
        run(cmd)

    print("[info] kadeflow finished ok")

if __name__ == "__main__":
    main()
