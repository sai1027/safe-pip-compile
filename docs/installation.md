# Installation

## Requirements

- Python **3.9 or later**
- `pip` (any recent version)

`safe-pip-compile` depends on [`pip-tools`](https://github.com/jazzband/pip-tools) (which provides `pip-compile`) and will install it automatically.

---

## Install from PyPI

```bash
pip install safe-pip-compile
```

That's it. The `safe-pip-compile` command is now available in your shell.

---

## Install in a virtual environment (recommended)

```bash
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

pip install safe-pip-compile
```

---

## Verify the installation

```bash
safe-pip-compile --version
```

---

## Upgrade

```bash
pip install --upgrade safe-pip-compile
```

---

## PyPI project page

[https://pypi.org/project/safe-pip-compile/](https://pypi.org/project/safe-pip-compile/)
