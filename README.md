# ECDAT — SIH Prototype

Enterprise Cryptographic Discovery & Analysis Tool.

## Local
Run `START-ECDAT.bat` and open the Flask URL shown by the launcher (default `http://127.0.0.1:5050`).

## Demo flow
1. Home → Start Discovery
2. Launch Safe Demo or upload `assets/ECDAT-real-world-test-dataset.zip`
3. Map → click a crypto node
4. Findings → open evidence / Why this category?
5. Risk Lab → change Z
6. Recommendations → inspect migration targets
7. Migration Simulator → run transition
8. CBOM → export JSON
9. Executive Mode → judge-ready summary

## GitHub + Render
Build: `pip install -r backend/requirements.txt`
Start: `gunicorn --chdir backend app:app`
The Flask app serves the frontend and API from the same origin in production.
