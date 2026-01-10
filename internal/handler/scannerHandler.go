package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"ssl-checker/internal/service"
	"strings"
	"time"
)

type ScannerHandler struct {
	Service *service.ScannerService
}

func NewScannerHandler(svc *service.ScannerService) *ScannerHandler {
	return &ScannerHandler{Service: svc}
}

// Index sirve la página principal
func (h *ScannerHandler) Index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/index.html")
}

// Check maneja la lógica de análisis y caché
func (h *ScannerHandler) Check(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 1. Intentar obtener del caché primero
	if report := h.Service.GetCachedReport(domain); report != nil {
		json.NewEncoder(w).Encode(report)
		return
	}

	// 2. Si no está en caché, iniciar/consultar análisis
	resChan, _ := h.Service.Analyze(r.Context(), domain)

	// Esperar el resultado con un select
	select {
	case report := <-resChan:
		if report != nil {
			// Si SSL Labs devuelve un estado de error interno
			if report.Status == "ERROR" {
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "ERROR",
					"message": report.StatusMessage,
				})
				return
			}
			json.NewEncoder(w).Encode(report)
		} else {
			lastChance := h.Service.GetCachedReport(domain)
			if lastChance != nil {
				json.NewEncoder(w).Encode(lastChance)
			} else {
				json.NewEncoder(w).Encode(map[string]string{"status": "PROCESSING"})
			}
		}
	case <-time.After(2 * time.Second):
		json.NewEncoder(w).Encode(map[string]string{"status": "WAITING"})
	}
}

// Download maneja la descarga del TXT con nombre dinámico
func (h *ScannerHandler) Download(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	report := h.Service.GetCachedReport(domain)

	if report == nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	content := h.Service.GenerateTXT(report)

	// Limpiar el nombre para el archivo: google.com -> report_google_com.txt
	safeName := strings.ReplaceAll(report.Host, ".", "_")
	fileName := fmt.Sprintf("report_%s.txt", safeName)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))

	w.Write([]byte(content))
}
