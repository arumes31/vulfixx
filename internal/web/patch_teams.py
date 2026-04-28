import os

file_path = r'c:\DR\Nextcloud\BUILD\vulfixx\internal\web\team_handlers_test.go'

with open(file_path, 'r') as f:
    content = f.read()

# Fix Success Leave (Not Active)
old_1 = """\t\t\tmockExpect: func(mock pgxmock.PgxPoolIface) {
\t\t\t\tmock.ExpectQuery("SELECT role FROM team_members").
\t\t\t\t\tWithArgs(10, 1).
\t\t\t\t\tWillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("member"))
\t\t\t\tmock.ExpectExec("DELETE FROM team_members").
\t\t\t\t\tWithArgs(10, 1).
\t\t\t\t\tWillReturnResult(pgxmock.NewResult("DELETE", 1))
\t\t\t\tmock.ExpectExec("INSERT INTO user_activity_logs").
\t\t\t\t\tWithArgs(1, "team_left", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
\t\t\t\t\tWillReturnResult(pgxmock.NewResult("INSERT", 1))
\t\t\t},"""

new_1 = """\t\t\tmockExpect: func(mock pgxmock.PgxPoolIface) {
\t\t\t\tmock.ExpectBegin()
\t\t\t\tmock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
\t\t\t\t\tWithArgs(10, 1).
\t\t\t\t\tWillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("member"))
\t\t\t\tmock.ExpectExec("DELETE FROM team_members").
\t\t\t\t\tWithArgs(10, 1).
\t\t\t\t\tWillReturnResult(pgxmock.NewResult("DELETE", 1))
\t\t\t\tmock.ExpectCommit()
\t\t\t\tmock.ExpectExec("INSERT INTO user_activity_logs").
\t\t\t\t\tWithArgs(1, "team_left", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
\t\t\t\t\tWillReturnResult(pgxmock.NewResult("INSERT", 1))
\t\t\t},"""

content = content.replace(old_1, new_1)

with open(file_path, 'w') as f:
    f.write(content)
