# Verification — tự kiểm trước khi nộp

- **OS / Python / Gitleaks:** Windows native (README ghi môi trường này chưa được pilot); Python 3.11.9; Gitleaks 8.30.1. Gitleaks binary nằm trong `.venv/Scripts` cho lần chạy này và được thêm vào `PATH` khi chạy pre-commit.
- **`python -m pytest tests/ -q`:** PASS, 33 passed.
- **PII test:** PASS; precision 1.000, recall 1.000 (118/118 entity).
- **`pre-commit run --all-files`:** PASS, hook `gitleaks-system` v8.30.1.
- **Dependency lock:** `pip install --require-hashes -r requirements.lock` PASS; tất cả package trong lock có SHA-256 hash.
- **Gitleaks current tree:** sạch với `.gitleaks.toml`; lịch sử có đúng một finding synthetic đã nêu trong `reports/secrets-incident.md`.
- **Before/after:** `reports/attack-before.log` có một POST synthetic; `reports/attack-after.log` rỗng (0 byte).
- **Ledger:** `verify(Path('reports/ledger.jsonl'))` trả về `True`; 23 entry, không thiếu reason; có deny `http_post` với reason và `on_behalf_of=dpo`.
- **Lỗi còn lại / giới hạn:** môi trường Windows native chưa được pilot theo README; các lệnh và 33 test đều chạy thành công tại đây. `--as` và mock chỉ mô phỏng identity/model, không đại diện production.
