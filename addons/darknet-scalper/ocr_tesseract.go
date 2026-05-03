//go:build cgo

package main

import (
	"github.com/otiai10/gosseract/v2"
)

func performOCR(imgData []byte) string {
	client := gosseract.NewClient()
	defer client.Close()

	if err := client.SetImageFromBytes(imgData); err != nil {
		return ""
	}
	
	text, _ := client.Text()
	return text
}
