## 2026-05-27 - Triggering csv.Writer Write Errors in Tests
**Learning:** `csv.Writer` uses a `bufio.Writer` internally (with a default buffer size of 4096 bytes). To trigger an error in the underlying `http.ResponseWriter` during a `csvWriter.Write(row)` call, the buffer must be filled or explicitly flushed.
**Action:** When testing for `Write` errors in CSV exports, either provide enough large rows to exceed the 4096-byte buffer or ensure that the error is expected at the `Flush()` call, which will attempt to push remaining buffered data.
