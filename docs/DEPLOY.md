# Deploying a public demo

A public demo should not run a model or expose the log database. It shows a **read-only snapshot**:
the case store (`cases.sqlite`) and case memory (`memory.sqlite`) produced by a real local run.
The UI only reads those two files, so the demo needs no MySQL, no model and no keys.

## 1. Produce the snapshot (locally)

```bash
python -m triage.cli ingest
python -m triage.cli investigate --limit 60
# review a handful in the UI so the review queue and metrics have content
mkdir -p demo && cp .triage/cases.sqlite .triage/memory.sqlite demo/
```

Everything in the snapshot comes from the public ExCyTIn dataset (already anonymised), so it is safe to
publish. Do not publish snapshots built from real company logs.

## 2a. Hugging Face Spaces (free)

1. Create a Space with the **Docker** SDK.
2. Add this repo's `Dockerfile.triage`, `requirements-triage.txt`, `triage/`, `agent/analyze.py`,
   `data/excytin/`, `results/` and `demo/`, plus this line before `USER app` in the Dockerfile:
   `COPY demo/ /app/.triage/`
3. Spaces expects port 7860: change the CMD's `--server.port=8501` to `7860`, or set `app_port: 8501` in the
   Space's README front matter.

## 2b. Render / Fly.io / Railway

Any service that builds a Dockerfile works. Build with `Dockerfile.triage`, expose port 8501, and bake in
the snapshot as above. No environment variables are required for read-only viewing.

## Demo GIF for the README

Record 20-30 seconds: queue → open an escalated case → expand a cited finding → entity graph → save a
review. On macOS: Cmd+Shift+5 to record, then convert with `ffmpeg -i demo.mov -vf "fps=10,scale=1000:-1" demo.gif`
and add it as `docs/demo.gif` at the top of the README.
