# Baseline — checkpoint 1

1. **Chưa có identity riêng cho mỗi run.** `agent/loop.py`, hàm `_naive_loop()`, không gắn principal, agent ID hay run ID vào các lần gọi tool.
2. **Không có policy gate cho phép `http_post`.** `_naive_loop()` gọi trực tiếp `tools.http_post()` sau khi mock nhận ra injection. `agent/tools.py`, hàm `http_post()`, chỉ kiểm tra allowlist localhost để giới hạn đích; đó không phải quyết định phân quyền.
3. **Bằng chứng rò rỉ nằm trong sink log.** `sink/sink.py`, handler `do_POST()`, ghi body của request vào `reports/sink.log`; bản sao trước containment sẽ là `reports/attack-before.log`. Baseline chưa có ledger để ghi lại decision hay lý do.
