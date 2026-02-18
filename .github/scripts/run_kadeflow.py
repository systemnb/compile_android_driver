#!/usr/bin/env python3
# .github/scripts/run_kadeflow.py

import os
import sys
import shlex
import yaml
import json
import time
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------
# Logging
# ---------------------------

def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def redact_value(s: str, patterns: List[str]) -> str:
    """
    Redact sensitive substrings in logs.
    Patterns are treated as literal substrings.
    """
    out = s
    for p in patterns:
        if p and p in out:
            out = out.replace(p, "***REDACTED***")
    return out

class Logger:
    def __init__(self, debug: bool = False, quiet: bool = False, log_file: str = "", redact_patterns: Optional[List[str]] = None, max_log_lines: int = 20000):
        self.debug = debug
        self.quiet = quiet
        self.log_file = log_file
        self.redact_patterns = redact_patterns or []
        self.max_log_lines = max_log_lines
        self._lines_written = 0
        self._fh = None
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(log_file, "w", encoding="utf-8")

    def close(self):
        if self._fh:
            self._fh.flush()
            self._fh.close()

    def _emit(self, level: str, msg: str):
        if self._lines_written >= self.max_log_lines:
            # Prevent runaway logs
            return
        line = f"[{now_ts()}] [{level}] {msg}"
        line = redact_value(line, self.redact_patterns)
        self._lines_written += 1
        if not self.quiet:
            print(line, flush=True)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def info(self, msg: str): self._emit("INFO", msg)
    def warn(self, msg: str): self._emit("WARN", msg)
    def error(self, msg: str): self._emit("ERROR", msg)
    def dbg(self, msg: str):
        if self.debug:
            self._emit("DEBUG", msg)

# ---------------------------
# Utils
# ---------------------------

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

def expand_env_in_obj(obj: Any) -> Any:
    """
    Recursively expand environment variables and ~ in all string values.
    """
    if isinstance(obj, dict):
        return {k: expand_env_in_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_env_in_obj(x) for x in obj]
    if isinstance(obj, str):
        return os.path.expandvars(os.path.expanduser(obj))
    return obj

def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}

def run_cmd_stream(logger: Logger, cmd: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, show_cmd: bool = True) -> Tuple[int, List[str]]:
    """
    Run a shell command, stream output line-by-line, return (rc, last_lines).
    """
    if show_cmd:
        logger.info(f"RUN: {cmd}")
        if cwd:
            logger.info(f"     cwd={cwd}")

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    last_lines: List[str] = []
    max_tail = 200  # store last 200 lines for error context

    assert proc.stdout is not None
    for line in proc.stdout:
        s = line.rstrip("\n")
        logger.info(s)
        last_lines.append(s)
        if len(last_lines) > max_tail:
            last_lines.pop(0)

    rc = proc.wait()
    return rc, last_lines

def find_plugin_dir(logger: Logger, plugin_name: str) -> Path:
    """
    Locate plugin directory in CI environment.
    Tries:
      1) lyenv plugin path <name>
      2) $LYENV_HOME/plugins/<name>
      3) search manifest.yaml under $LYENV_HOME
    """
    # 1) lyenv plugin path
    try:
        out = subprocess.check_output(["bash", "-lc", f"lyenv plugin path {shlex.quote(plugin_name)}"], text=True).strip()
        p = Path(out).expanduser().resolve()
        if p.exists():
            logger.info(f"plugin_dir resolved by 'lyenv plugin path': {p}")
            return p
    except Exception as e:
        logger.dbg(f"lyenv plugin path failed: {e}")

    lyenv_home = os.environ.get("LYENV_HOME", "")
    if lyenv_home:
        # 2) common layout
        p = Path(lyenv_home).joinpath("plugins", plugin_name)
        if p.exists():
            logger.info(f"plugin_dir resolved by $LYENV_HOME/plugins: {p.resolve()}")
            return p.resolve()

        # 3) search manifest.yaml
        root = Path(lyenv_home)
        for m in root.rglob("manifest.yaml"):
            try:
                txt = m.read_text(encoding="utf-8", errors="ignore")
                if f"name: {plugin_name}" in txt:
                    logger.info(f"plugin_dir resolved by manifest search: {m.parent.resolve()}")
                    return m.parent.resolve()
            except Exception:
                continue

    raise RuntimeError(f"Cannot locate plugin directory for '{plugin_name}' (LYENV_HOME={lyenv_home})")

def safe_summary(obj: Any, limit: int = 4000) -> str:
    """
    JSON summary for logs (limited size).
    """
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True)
        if len(s) > limit:
            return s[:limit] + "...(truncated)"
        return s
    except Exception:
        return str(obj)

def dump_env(logger: Logger):
    """
    Print key environment values helpful for CI debugging (redacted).
    """
    keys = [
        "GITHUB_WORKSPACE",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "RUNNER_OS",
        "RUNNER_TEMP",
        "LYENV_HOME",
        "PATH",
    ]
    for k in keys:
        v = os.environ.get(k, "")
        if k == "PATH" and len(v) > 300:
            v = v[:300] + "...(truncated)"
        logger.info(f"ENV {k}={v}")

# ---------------------------
# Main flow
# ---------------------------

def main():
    # -------- parse args --------
    config_path = None
    debug = False
    quiet = False
    log_file = ""
    max_log_lines = 20000
    redact_patterns: List[str] = []

    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--config" and i + 1 < len(argv):
            config_path = Path(argv[i + 1]).resolve()
            i += 2
            continue
        if a == "--debug":
            debug = True
            i += 1
            continue
        if a == "--quiet":
            quiet = True
            i += 1
            continue
        if a == "--log-file" and i + 1 < len(argv):
            log_file = argv[i + 1]
            i += 2
            continue
        if a == "--max-log-lines" and i + 1 < len(argv):
            try:
                max_log_lines = int(argv[i + 1])
            except Exception:
                max_log_lines = 20000
            i += 2
            continue
        if a == "--redact" and i + 1 < len(argv):
            redact_patterns.append(argv[i + 1])
            i += 2
            continue
        i += 1

    if not config_path or not config_path.exists():
        raise SystemExit("Missing --config <kadeflow.yaml> or file not found.")

    # Auto-redact common secrets if present
    for k in ["GITHUB_TOKEN", "TOKEN", "SECRET", "PASSWORD"]:
        v = os.environ.get(k, "")
        if v:
            redact_patterns.append(v)

    logger = Logger(debug=debug, quiet=quiet, log_file=log_file, redact_patterns=redact_patterns, max_log_lines=max_log_lines)

    try:
        logger.info("kadeflow runner started")
        logger.info(f"python={sys.executable}")
        logger.info(f"cwd={os.getcwd()}")
        dump_env(logger)

        # -------- load config --------
        flow = load_yaml(config_path)
        logger.info(f"Loaded config: {config_path}")
        logger.dbg(f"Config full (summary): {safe_summary(flow)}")

        project_name = flow.get("project", {}).get("name", "ci-kade")
        plugin_name = flow.get("project", {}).get("plugin", "kade")
        plugin_source = flow.get("project", {}).get("plugin_source", "")

        logger.info(f"project.name={project_name}")
        logger.info(f"project.plugin={plugin_name}")
        if plugin_source:
            logger.info(f"project.plugin_source={plugin_source}")

        # -------- install plugin --------
        if plugin_source:
            rc, tail = run_cmd_stream(logger, f"lyenv plugin install {shlex.quote(plugin_source)}")
        else:
            rc, tail = run_cmd_stream(logger, f"lyenv plugin install {shlex.quote(plugin_name)}")

        if rc != 0:
            logger.error(f"Plugin install failed rc={rc}")
            raise SystemExit(rc)

        plugin_dir = find_plugin_dir(logger, plugin_name)
        cfg_path = plugin_dir / "config.yaml"

        # -------- apply config overrides to plugin config.yaml --------
        overrides = flow.get("kade", {}).get("config_overrides", {}) or {}
        overrides = expand_env_in_obj(overrides)

        # Log key fields (important for debugging path issues)
        def _get(d, path, default=""):
            cur = d
            for part in path.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return default
            return cur

        kernel_flavor = _get(overrides, "kernel.flavor", "")
        logger.info(f"[overrides] kernel.flavor={kernel_flavor}")

        # Show driver path (gki)
        ext_src = _get(overrides, "gki.driver.external_src_dir", "")
        if ext_src:
            logger.info(f"[overrides] gki.driver.external_src_dir={ext_src}")

        # Load existing plugin config if present
        base_cfg = {}
        if cfg_path.exists():
            try:
                base_cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            except Exception as e:
                logger.warn(f"Failed to parse existing plugin config.yaml: {e}")

        merged_cfg = deep_merge(base_cfg, overrides)

        # Write back plugin config
        cfg_path.write_text(yaml.safe_dump(merged_cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
        logger.info(f"Wrote plugin config: {cfg_path}")

        # Print a short config digest
        logger.dbg(f"plugin config (summary): {safe_summary(merged_cfg)}")

        # -------- build command list --------
        steps = flow.get("flow", {}).get("steps", []) or []
        post_cmds = flow.get("flow", {}).get("post_commands", []) or []

        # ABI injection logic
        abi = flow.get("abi", {}) or {}
        upstream_patch = bool(abi.get("upstream_patch", True))

        # Ensure abi_upstream exists if enabled
        if upstream_patch and not any(s.strip().startswith("kade abi_upstream") for s in steps):
            inserted = False
            for idx, s in enumerate(steps):
                if s.strip().startswith("kade build"):
                    steps.insert(idx, "kade abi_upstream")
                    inserted = True
                    break
            if not inserted:
                steps.append("kade abi_upstream")

        # Inject kade abi command if symbols provided
        abi_cmd = ""
        symbols_file = abi.get("symbols_file", "")
        symbols = abi.get("symbols", [])
        do_sort = bool(abi.get("sort", False))
        do_replace = bool(abi.get("replace", False))

        if symbols_file:
            symfile = os.path.expandvars(os.path.expanduser(str(symbols_file)))
            abi_cmd = f"kade abi {'--replace ' if do_replace else ''}{'--sort ' if do_sort else ''}--file {shlex.quote(symfile)}"
        elif isinstance(symbols, list) and symbols:
            sym_args = " ".join(shlex.quote(str(x)) for x in symbols)
            abi_cmd = f"kade abi {'--replace ' if do_replace else ''}{'--sort ' if do_sort else ''}{sym_args}"

        if abi_cmd:
            inserted = False
            for idx, s in enumerate(steps):
                if s.strip().startswith("kade build"):
                    steps.insert(idx, abi_cmd)
                    inserted = True
                    break
            if not inserted:
                steps.append(abi_cmd)

        # Expand variables in commands and log final plan
        env = os.environ.copy()
        expanded_steps = [os.path.expandvars(os.path.expanduser(s)) for s in steps]
        expanded_post = [os.path.expandvars(os.path.expanduser(s)) for s in post_cmds]

        logger.info("Execution plan (steps):")
        for s in expanded_steps:
            logger.info(f"  - {s}")
        if expanded_post:
            logger.info("Execution plan (post_commands):")
            for s in expanded_post:
                logger.info(f"  - {s}")

        # -------- run steps --------
        for cmd in expanded_steps:
            rc, tail = run_cmd_stream(logger, cmd, cwd=os.getcwd(), env=env)
            if rc != 0:
                logger.error(f"Command failed rc={rc}: {cmd}")
                logger.error("Last output lines:")
                for line in tail[-60:]:
                    logger.error(line)
                # Common hints
                logger.error("Hints:")
                logger.error("  - Check whether env vars in paths were expanded correctly.")
                logger.error("  - If using 'kade abi --file', verify the file exists and contains valid symbol names.")
                logger.error("  - If you see '__KSYM_/path/to/file', a file path was treated as a symbol. Check ABI injection and symbols file contents.")
                raise SystemExit(rc)

        # -------- run post commands --------
        for cmd in expanded_post:
            rc, tail = run_cmd_stream(logger, cmd, cwd=os.getcwd(), env=env)
            if rc != 0:
                logger.error(f"Post command failed rc={rc}: {cmd}")
                logger.error("Last output lines:")
                for line in tail[-60:]:
                    logger.error(line)
                raise SystemExit(rc)

        logger.info("kadeflow runner finished successfully")

    finally:
        logger.close()

if __name__ == "__main__":
    main()
