import re

with open('internal/worker/sync_advisory_rss.go', 'r') as f:
    content = f.read()

new_str = """		uniqueCVEs := slices.Clone(foundCVEs)
		slices.Sort(uniqueCVEs)
		uniqueCVEs = slices.Compact(uniqueCVEs)"""

content = re.sub(r'\t\tvar uniqueCVEs \[\]string\n\t\tfor _, cve := range foundCVEs \{\n\t\t\tuniqueCVEs = append\(uniqueCVEs, cve\)\n\t\t\}\n\t\tslices\.Sort\(uniqueCVEs\)\n\t\tuniqueCVEs = slices\.Compact\(uniqueCVEs\)', new_str, content, flags=re.DOTALL)
if new_str not in content:
    # Try an easier match
    content = content.replace("var uniqueCVEs []string\n\t\tfor _, cve := range foundCVEs {\n\t\t\tuniqueCVEs = append(uniqueCVEs, cve)\n\t\t}\n\t\tslices.Sort(uniqueCVEs)\n\t\tuniqueCVEs = slices.Compact(uniqueCVEs)", new_str)

with open('internal/worker/sync_advisory_rss.go', 'w') as f:
    f.write(content)
