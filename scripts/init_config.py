"""Copy the installed configuration; disable only the top-level run-as block."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]

def disable_run_as(text):
    lines = text.splitlines(keepends=True)
    result, in_block = [], False
    for line in lines:
        if line.startswith("run-as:"):
            in_block = True
            result.append("# " + line)
        elif in_block and (not line.strip() or line[0].isspace() or line.startswith("#")):
            result.append("# " + line if line.strip() and not line.lstrip().startswith("#") else line)
        else:
            in_block = False
            result.append(line)
    return "".join(result)

def main():
    source = Path("/etc/suricata")
    target = ROOT / "config"
    target.mkdir(exist_ok=True)
    if (target / "suricata.yaml").exists():
        raise SystemExit("config/suricata.yaml already exists; keeping it unchanged.")
    # Preserve sibling configuration files used by the Arch package.
    for file in source.iterdir():
        if file.is_file() and file.suffix in (".yaml", ".config"):
            if not (target / file.name).exists():
                shutil.copyfile(file, target / file.name)
    config = target / "suricata.yaml"
    if not config.exists():
        raise SystemExit("No installed suricata.yaml found; install Suricata first.")
    config.write_text(disable_run_as(config.read_text()))
    (ROOT / "cache/sgh").mkdir(parents=True, exist_ok=True)
    print(f"Prepared {config}; validate it with scripts/run_ids.py.")

if __name__ == "__main__":
    main()
