package worker

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// WrapInModernLayout wraps the provided title and content in a standard premium HTML email template.
// SECURITY: The 'content' parameter is interpolated directly into the HTML. Callers MUST ensure
// that 'content' contains trusted or pre-sanitized HTML. User-controlled input MUST be
// sanitized or HTML-escaped before being passed to this function to prevent XSS.
func WrapInModernLayout(title, content string) string {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	logoURL := baseURL + "/static/img/logo.png"
	escapedTitle := html.EscapeString(title)

	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #0c0e12;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            color: #dfe2eb;
            -webkit-font-smoothing: antialiased;
        }
        .wrapper {
            width: 100%%;
            table-layout: fixed;
            background-color: #0c0e12;
            padding-bottom: 40px;
        }
        .main {
            background-color: #101418;
            margin: 0 auto;
            width: 100%%;
            max-width: 600px;
            border-spacing: 0;
            border-radius: 24px;
            border: 1px solid #232931;
            overflow: hidden;
            margin-top: 40px;
        }
        .header {
            padding: 40px 0 20px 0;
            text-align: center;
        }
        .content {
            padding: 0 40px 40px 40px;
        }
        .footer {
            padding: 20px 0;
            text-align: center;
            font-size: 12px;
            color: #5b6271;
        }
        .logo {
            width: 48px;
            height: auto;
            margin-bottom: 16px;
        }
        h1 {
            color: #ffffff;
            font-size: 24px;
            font-weight: 700;
            margin: 0 0 20px 0;
            letter-spacing: -0.02em;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            margin: 0 0 20px 0;
        }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #00daf3 0%%, #0099ff 100%%);
            color: #101418 !important;
            text-decoration: none !important;
            padding: 16px 32px;
            border-radius: 14px;
            font-weight: 700;
            font-size: 15px;
            margin: 10px 0;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .secondary-btn {
            display: inline-block;
            background: #1c2026;
            color: #dfe2eb !important;
            text-decoration: none !important;
            padding: 14px 28px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 13px;
            border: 1px solid #232931;
            margin: 10px 0;
        }
        .divider {
            height: 1px;
            background-color: #232931;
            margin: 30px 0;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <table class="main" align="center">
            <tr>
                <td class="header">
                    <img src="%s" alt="Vulfixx" class="logo" width="48">
                    <div style="font-weight: 800; letter-spacing: 0.1em; color: #ffffff; text-transform: uppercase; font-size: 14px;">Vulfixx</div>
                </td>
            </tr>
            <tr>
                <td class="content">
                    <h1 align="center">%s</h1>
                    %s
                </td>
            </tr>
        </table>
        <div class="footer">
            &copy; %d Vulfixx Threat Intelligence. All rights reserved.<br>
            Sent from the Vulfixx Security Operations Center.
        </div>
    </div>
</body>
</html>
	`, logoURL, escapedTitle, content, time.Now().Year())
}
