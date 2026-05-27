1. **Analyze N+1 Query on cisa_ransomware:**
   In `internal/web/dashboard_handlers.go`, inside `DashboardHandler` and `fetchPublicDashboardCVEs`, there is a loop iterating over queried CVEs:
   ```go
   _ = a.Pool.QueryRow(r.Context(), "SELECT cisa_ransomware FROM cves WHERE id = $1", c.ID).Scan(&c.CISARansomware)
   ```
   This executes an additional query for each CVE row to populate `c.CISARansomware`, causing an N+1 query issue.

2. **Develop Solution:**
   To fix this without changing the 22-column structure of the main query (which would break dozens of `pgxmock` definitions), we can batch all the `cisa_ransomware` queries into a single query after fetching the CVEs.
   Instead of:
   ```go
   for rows.Next() {
       // scan
       _ = a.Pool.QueryRow(ctx, "SELECT cisa_ransomware FROM cves WHERE id = $1", c.ID).Scan(&c.CISARansomware)
       cves = append(cves, c)
   }
   ```
   We can do:
   ```go
   var cveIDs []int
   for rows.Next() {
       // scan
       cves = append(cves, c)
       cveIDs = append(cveIDs, c.ID)
   }
   if len(cveIDs) > 0 {
       rRows, err := a.Pool.Query(ctx, "SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)", cveIDs)
       if err == nil {
           defer rRows.Close()
           rMap := make(map[int]bool)
           for rRows.Next() {
               var id int
               var cr bool
               if rRows.Scan(&id, &cr) == nil {
                   rMap[id] = cr
               }
           }
           for i := range cves {
               cves[i].CISARansomware = rMap[cves[i].ID]
           }
       }
   }
   ```
   Wait, if we do this, the tests using `pgxmock` will fail because they expect the N queries `SELECT cisa_ransomware FROM cves WHERE id = $1`. We will need to update those expectations to expect `SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)`.
   Let's check `CVEDetailHandler`. It executes `SELECT cisa_ransomware FROM cves WHERE cve_id = $1` which is fine since it's just 1 CVE. So we won't change that.

3. **Affected test files:**
   - `internal/web/performance_bench_test.go`
   - `internal/web/base_handlers_test.go`
   - `internal/web/dashboard_handlers_test.go`

   We need to change the query regex to match `WHERE id = ANY` and the return rows to include `id` and `cisa_ransomware`.
   For example, in `dashboard_handlers_test.go`:
   ```go
   mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY")).
       WithArgs(pgxmock.AnyArg()).
       WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))
   ```

4. **Verify Implementation:**
   - Update `DashboardHandler` and `fetchPublicDashboardCVEs` to batch the query.
   - Update tests.
   - Run `go test ./internal/web` and `go test -bench=BenchmarkDashboardHandler -run=^$ ./internal/web`.

5. **Pre-commit:**
   - Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.

6. **Submit:**
   - Create PR with title "⚡ Bolt: [performance improvement] Fix N+1 query for cisa_ransomware"
