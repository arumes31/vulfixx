//go:build !cgo

package main

import (
	"errors"
	"log"
)

func performOCR(imgData []byte) (string, error) {
	_ = imgData
	log.Println("OCR: Tesseract not available in this build (CGO disabled or missing libs)")
	return "", errors.New("tesseract OCR unavailable in this build")
}
