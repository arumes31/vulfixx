//go:build cgo

package main

import (
	"log"

	"github.com/otiai10/gosseract/v2"
)

func performOCR(imgData []byte) string {
	client := gosseract.NewClient()
	defer client.Close()

	if err := client.SetImageFromBytes(imgData); err != nil {
		log.Printf("OCR SetImageFromBytes error: %v", err)
		return ""
	}
	
	text, err := client.Text()
	if err != nil {
		log.Printf("OCR error: %v", err)
		return ""
	}
	return text
}
