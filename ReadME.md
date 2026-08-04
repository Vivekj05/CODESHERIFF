# CodeSheriff

CodeSheriff is an AI-powered security auditing system for GitHub Pull Requests. It automatically listens for pull request events, extracts the changed code, and will analyze it using multiple AI agents to detect security vulnerabilities.

> 🚧 This repository is currently under development.

## Features

- GitHub Webhook Integration
- Detects Pull Request Open events
- Extracts changed files and code patches
- Posts comments back to the Pull Request
- Built with FastAPI

## Tech Stack

- Python
- FastAPI
- GitHub REST API
- GitHub Webhooks

## Project Structure

```
codesheriff/
│── main.py               # FastAPI webhook server
│── github_service.py     # GitHub API helper functions
│── .env                  # Environment variables
│── requirements.txt
```

## Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd codesheriff
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

Windows

```bash
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root.

```env
GITHUB_TOKEN=your_github_personal_access_token
```

### 5. Run the application

```bash
uvicorn main:app --reload
```

The webhook endpoint will be available at:

```
http://localhost:8000/webhook
```

## Current Workflow

```
GitHub Pull Request
        │
        ▼
GitHub Webhook
        │
        ▼
FastAPI Server
        │
        ▼
Extract PR Information
        │
        ▼
Fetch Changed Files & Patches
        │
        ▼
Post Placeholder Comment
```

## Roadmap

- [x] GitHub Webhook Integration
- [x] Pull Request Event Detection
- [x] PR Diff Extraction
- [ ] Orchestrator
- [ ] Static Analysis Agent
- [ ] Semantic Analysis Agent
- [ ] Context Agent
- [ ] Judge Agent
- [ ] Patch Generator
- [ ] Verification Agent
- [ ] React Dashboard

## License

This project is developed as a Final Year B.Tech Project.