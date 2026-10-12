# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner:** Gitleaks v8.30.1, dùng `.gitleaks.toml` và bật `--redact`.
- **Commit:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- **Finding lịch sử:** file `lab-fake-secret.txt`, rule `lab24-synthetic-token`, một finding tại commit trên. Đây là token demo vô hiệu được đề bài cài sẵn, không phải credential thật.
- **File hiện tại:** `gitleaks dir --config .gitleaks.toml --redact --verbose .` sạch; scanner quét khoảng 295 KB. `.venv/` được allowlist vì đây là môi trường cài package cục bộ, không phải nội dung submission.
- **Nếu là credential thật:** thu hồi hoặc rotate ngay tại issuer, điều tra phạm vi sử dụng và thay credential ở các consumer; sau đó xử lý lịch sử theo quy trình incident. Xoá file khỏi HEAD không làm credential đã lộ mất hiệu lực.
- **Vì sao các control khác chưa đủ:** lock hash giúp xác minh package được cài đúng phiên bản/nội dung đã khóa; pre-commit giúp phát hiện một số secret mới trước commit. Không điều nào thu hồi secret đã lộ trong lịch sử, nên rotate/revoke vẫn là bước bắt buộc.
