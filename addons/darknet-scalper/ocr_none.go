//go:build !cgo

package main

import "log"

func performOCR(imgData []byte) string {
	_ = imgData
	log.Println("OCR: Tesseract not available in this build (CGO disabled or missing libs)")
	return ""
}
