import re

# Fix extra_worker_test.go
with open('internal/worker/extra_worker_test.go', 'r') as f:
    content = f.read()

# 1. TestStartWorkerCleanExit ignores errors from SetupTestDB and SetupTestRedis
old_clean = """func TestStartWorkerCleanExit(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	_, _ = db.SetupTestRedis()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)"""
new_clean = """func TestStartWorkerCleanExit(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup test db: %v", err)
	}
	defer mock.Close()
	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("setup test redis: %v", err)
	}
	defer mr.Close()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)"""
content = content.replace(old_clean, new_clean)

# 2. TestFetchCVEsPeriodically_Cancel
old_fetch = """func TestFetchCVEsPeriodically_Cancel(t *testing.T) {
	mock, _ := db.SetupTestDB()
	_, _ = db.SetupTestRedis()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)"""
new_fetch = """func TestFetchCVEsPeriodically_Cancel(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup test db: %v", err)
	}
	defer mock.Close()
	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("setup test redis: %v", err)
	}
	defer mr.Close()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)"""
content = content.replace(old_fetch, new_fetch)

# 3. EPSS_Non200 - Add ExpectationsWereMet
old_epss = """		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-1"))
		w.syncEPSS(ctx)
	})"""
new_epss = """		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-1"))
		w.syncEPSS(ctx)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})"""
content = content.replace(old_epss, new_epss)

# 4. NVD_ErrorCodes - Add ExpectationsWereMet
old_nvd = """				w.runFullSync(shortCtx, true)
			})"""
new_nvd = """				w.runFullSync(shortCtx, true)
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("unmet expectations: %v", err)
				}
			})"""
content = content.replace(old_nvd, new_nvd)

# 5. extra_worker_test.go last_run sync mock check
old_runfull = """		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		
		// Use a short timeout context to break the loop/sleep
		shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		
		w.runFullSync(shortCtx, false)
	})"""
new_runfull = """		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		
		// Use a short timeout context to break the loop/sleep
		shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		
		w.runFullSync(shortCtx, false)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})"""
content = content.replace(old_runfull, new_runfull)

with open('internal/worker/extra_worker_test.go', 'w') as f:
    f.write(content)

# Fix extra_handlers_test.go
with open('internal/web/extra_handlers_test.go', 'r') as f:
    hc = f.read()

# ReadyzHandler_Success
hc = hc.replace("""		app.ReadyzHandler(rr, req)
		if rr.Code != http.StatusOK {""", """		app.ReadyzHandler(rr, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr.Code != http.StatusOK {""")

# ReadyzHandler_DBDown
hc = hc.replace("""		app.ReadyzHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {""", """		app.ReadyzHandler(rr, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr.Code != http.StatusServiceUnavailable {""")

# Success_Private
hc = hc.replace("""		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK && rr2.Code != http.StatusBadRequest {""", """		app.UpdateCVENoteHandler(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusOK && rr2.Code != http.StatusBadRequest {""")

# Success_Team
hc = hc.replace("""		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK {""", """		app.UpdateCVENoteHandler(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusOK {""")

# Acknowledge
hc = hc.replace("""		app.HandleAlertAction(rrPost, reqPost)
		if rrPost.Code != http.StatusOK {""", """		app.HandleAlertAction(rrPost, reqPost)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rrPost.Code != http.StatusOK {""")

# InvalidCredentials
hc = hc.replace("""		app.LoginHandler(rr, req)
		if rr.Code != http.StatusOK { // Re-renders login page with error""", """		app.LoginHandler(rr, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr.Code != http.StatusOK { // Re-renders login page with error""")

# AuthMiddleware_Unverified
hc = hc.replace("""		app.AuthMiddleware(nextHandler).ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {""", """		app.AuthMiddleware(nextHandler).ServeHTTP(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusForbidden {""")

# AdminMiddleware_NonAdmin
hc = hc.replace("""		app.AdminMiddleware(nextHandler).ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {""", """		app.AdminMiddleware(nextHandler).ServeHTTP(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusForbidden {""")

# AdminUserManagementHandler_Success
hc = hc.replace("""		app.AdminUserManagementHandler(rr2, req)
		if rr2.Code != http.StatusOK {""", """		app.AdminUserManagementHandler(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusOK {""")

# AdminDeleteUserHandler_Success
hc = hc.replace("""		app.AdminDeleteUserHandler(rr2, req)
		if rr2.Code != http.StatusFound {""", """		app.AdminDeleteUserHandler(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusFound {""")

with open('internal/web/extra_handlers_test.go', 'w') as f:
    f.write(hc)
