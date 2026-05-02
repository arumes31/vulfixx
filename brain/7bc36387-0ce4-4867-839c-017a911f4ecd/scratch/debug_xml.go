package main

import (
	"encoding/xml"
	"fmt"
)

type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []RSSItem `xml:"item"`
	} `xml:"channel"`
}

type RSSItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
}

func main() {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
    <item>
        <title>Cisco IOS - Test Advisory</title>
        <link>https://cisco.com/psirt/123</link>
        <description>Vulnerability in Cisco IOS CVE-2024-9999</description>
    </item>
</channel>
</rss>`

	var rss RSSFeed
	err := xml.Unmarshal([]byte(xmlContent), &rss)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Items found: %d\n", len(rss.Channel.Items))
	for _, item := range rss.Channel.Items {
		fmt.Printf("Title: %s\n", item.Title)
	}
}
