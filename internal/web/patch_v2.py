import os

file_path = r'c:\DR\Nextcloud\BUILD\vulfixx\internal\web\coverage_improvement_v2_test.go'

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'app.LoginHandler(rr, req)' in line:
        # Check if it's not the already patched one at line 43 (approx)
        # Actually, let's just patch all of them and see what happens.
        # But we only want it for cases that render templates.
        # For simplicity, I'll just patch all and if some don't need it, I'll fix them.
        # Wait, if I add it to ones that redirect, they will fail with UNMET expectations.
        new_lines.append('\t\texpectBaseQueries(mock, 1)\n')
    new_lines.append(line)

with open(file_path, 'w') as f:
    f.writelines(new_lines)
