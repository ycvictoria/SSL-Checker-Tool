package main

import (
	"fmt"
	"net/http"
	"ssl-checker/internal/handler"
	"ssl-checker/internal/repository"
	"ssl-checker/internal/service"
)

func main() {
	// 1. Inicializar dependencias
	repo := &repository.SSLLabsRepo{APIURL: "https://api.ssllabs.com/api/v3/analyze"}
	svc := service.NewScannerService(repo)
	h := handler.NewScannerHandler(svc) // Instanciar el nuevo handler

	// 2. Servir archivos estáticos
	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// 3. Rutas usando la clase ScannerHandler
	http.HandleFunc("/", h.Index)
	http.HandleFunc("/check", h.Check)
	http.HandleFunc("/download", h.Download)

	fmt.Println("🚀 Servidor en http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error al iniciar el servidor: %v\n", err)
	}
}

/*
func main() {
	repo := &repository.SSLLabsRepo{APIURL: "https://api.ssllabs.com/api/v3/analyze"}
	svc := service.NewScannerService(repo)
	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	// Handler funciones
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	})
	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			return
		}

		// 1. Intentar obtener del caché primero si el log dice que ya terminó
		if report := svc.GetCachedReport(domain); report != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(report)
			return
		}

		// 2. Si no está en caché, iniciar/consultar análisis
		resChan, _ := svc.Analyze(r.Context(), domain)

		w.Header().Set("Content-Type", "application/json")

		// Esperar el resultado del canal con un timeout
		select {
		case report := <-resChan:
			if report != nil {
				json.NewEncoder(w).Encode(report)
			} else {
				// Si el canal mandó nil, intentamos una última vez al caché
				lastChance := svc.GetCachedReport(domain)
				if lastChance != nil {
					json.NewEncoder(w).Encode(lastChance)
				} else {
					json.NewEncoder(w).Encode(map[string]string{"status": "PROCESSING"})
				}
			}
		case <-time.After(2 * time.Second):
			// Si el canal tarda, devolvemos lo que tengamos
			json.NewEncoder(w).Encode(map[string]string{"status": "WAITING"})
		}
	})
	http.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		report := svc.GetCachedReport(domain)
		if report != nil {
			content := svc.GenerateTXT(report)
			w.Header().Set("Content-Disposition", "attachment; filename=report.txt")
			w.Write([]byte(content))
		}
	})

	fmt.Println("🚀 Servidor en http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
*/
