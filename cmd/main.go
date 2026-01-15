package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"ssl-checker/internal/handler"
	"ssl-checker/internal/repository"
	"ssl-checker/internal/service"
)

func main() {
	// 1. Inicializar dependencias
	repo := &repository.SSLLabsRepo{APIURL: "https://api.ssllabs.com/api/v3/analyze"}
	svc := service.NewScannerService(repo)

	//for persistence
	svc.LoadFromDisk()
	h := handler.NewScannerHandler(svc) // Instanciar el nuevo handler

	// 2. Servir archivos estáticos
	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// 3. Rutas usando la clase ScannerHandler
	http.HandleFunc("/", h.Index)
	http.HandleFunc("/check", h.Check)
	http.HandleFunc("/download", h.Download)

	http.HandleFunc("/downloadAll", h.DownloadAllSearchedSites)

	fmt.Println("🚀 Servidor en http://localhost:8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error al iniciar el servidor: %v\n", err)
	}

	//option for console iu interface
	//consoleOptions(svc)
}

func consoleOptions(svc *service.ScannerService) {
	for { // Bucle infinito para que el menú siempre regrese
		fmt.Println("\n==============================")
		fmt.Println("      SSL CHECKER MENU")
		fmt.Println("==============================")
		fmt.Println("1. Analizar un nuevo dominio")
		fmt.Println("2. Salir")
		fmt.Print("\nSelecciona una opción: ")

		var menuOption string
		fmt.Scanln(&menuOption)

		if menuOption == "2" {
			fmt.Println("👋 ¡Hasta luego!")
			break // Rompe el bucle for y sale de la función
		}

		if menuOption == "1" {
			runAnalysisConsole(svc) // Ejecutamos el análisis en una sub-función
		} else {
			fmt.Println("⚠️ Opción no válida, intenta de nuevo.")
		}
	}
}
func runAnalysisConsole(svc *service.ScannerService) {
	var domain string
	fmt.Println("🔍1.  Ingresa el dominio a analizar (ej: google.com): ")
	fmt.Scanln(&domain)
	fmt.Printf("\n🚀 Iniciando análisis de %s...\n", domain)
	resChan, errChan := svc.Analyze(context.Background(), domain)

	for {
		select {
		case err := <-errChan:
			if err != nil {
				fmt.Printf("\n Error %v", err)
				return
			}

		case report, ok := <-resChan:
			if !ok {
				return
			}
			fmt.Printf("\r🔄 Status: %s...", report.Status)

			if report.Status == "READY" {
				var reportComplete string = svc.GenerateTXT(report)
				fmt.Println("\nComplete analysis")
				fmt.Println(reportComplete)

				fmt.Println("Do you want to download the data of this domain? Digit Y or N : ")
				var resp string
				fmt.Scanln(&resp)
				if resp == "y" || resp == "Y" {
					filename := domain + " report.txt"
					err := os.WriteFile(filename, []byte(reportComplete), 0644)
					if err != nil {
						fmt.Printf("err when saving data:  %v ", err)
						return
					} else {
						fmt.Printf("Data file saved:  %s", filename)
					}

				} else {
					fmt.Println("Analysis complete. Not saved on file.")

				}

				fmt.Println("\nPresiona Enter para volver al menú...")
				fmt.Scanln() // Pausa para que el usuario lea antes de limpiar
				return       // Sale y vuelve al for del menú

			}
		}

	}
}
