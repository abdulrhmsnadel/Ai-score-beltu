# GitHub Private Repository Setup

This repository is prepared for a **private** GitHub repository.

## 1. Create the repository

On GitHub, create a new repository named:

`AI-SCORE-BELTU`

Set **Visibility** to **Private**. Do not initialize it with another README, `.gitignore`, or license because those files already exist here.

## 2. Upload with Git

From this project directory:

```bash
git init
git branch -M main
git add .
git status
git commit -m "Initial AI-SCORE-BELTU framework"
```

Add the remote for your own GitHub repository, then push:

```bash
git remote add origin YOUR_PRIVATE_REPOSITORY_URL
git push -u origin main
```

Replace `YOUR_PRIVATE_REPOSITORY_URL` with the URL GitHub gives you. Never paste credentials into the repository files.

## 3. Recommended repository settings

Enable branch protection for `main` when the project becomes collaborative. Keep secret scanning and push protection enabled when available. Require pull requests and passing CI before merging.

## 4. Before the first push

Check that no local artifacts are present:

```bash
git status --short
find . -maxdepth 3 -type f | sort
```

The root `.gitignore` already excludes virtual environments, caches, databases, `.env`, build artifacts, and editor metadata.

## 5. First local verification

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest -q
beltu --help
beltu -e
beltu -d
```

## Local install after cloning

```bash
chmod +x install.sh
./install.sh
```

Then run:

```bash
beltu -h
beltu -d
beltu -e
```

