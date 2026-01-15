package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"ssl-checker/internal/model"
	"ssl-checker/internal/repository"
	"strings"
	"sync"
	"time"
)

const dbFile = "scans_db.json"

type ScannerService struct {
	Repo        *repository.SSLLabsRepo
	activeScans map[string]*model.SSLReport
	mu          sync.RWMutex
}

func NewScannerService(repo *repository.SSLLabsRepo) *ScannerService {
	return &ScannerService{
		Repo:        repo,
		activeScans: make(map[string]*model.SSLReport),
	}
}

func (s *ScannerService) Analyze(ctx context.Context, host string) (<-chan *model.SSLReport, <-chan error) {
	resChan := make(chan *model.SSLReport)
	errChan := make(chan error)

	go func() {
		defer close(resChan)
		defer close(errChan)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				report, code, err := s.Repo.FetchData(host)
				if err != nil {
					errChan <- fmt.Errorf("error de conexión con SSL Labs")
					return
				}

				// Manejo de Rate Limit
				if code == 429 || code == 529 {
					log.Printf("⚠️ Rate limit alcanzado para %s, esperando...", host)
					time.Sleep(30 * time.Second)
					continue
				}

				if report.Status == "ERROR" {
					errChan <- fmt.Errorf("error de API: %s", report.StatusMessage)
					return
				}

				// Actualizar caché interna con Mutex
				s.mu.Lock()
				s.activeScans[host] = report
				s.mu.Unlock()

				log.Printf("🔄 [Progreso %s]: %d%% - Status: %s", host, report.Status)

				// ✅ EL CAMBIO CLAVE: Primero enviamos el reporte al canal
				resChan <- report

				// Si el estado es READY, imprimimos éxito y salimos de la goroutine
				if report.Status == "READY" {
					log.Printf("✅ [TERMINADO]: Análisis de %s completado.", host)
					s.SaveToDisk()
					return
				}

				// Esperar antes de la siguiente consulta (SSL Labs recomienda 5-10s)
				time.Sleep(10 * time.Second)
			}
		}
	}()

	return resChan, errChan
}
func (s *ScannerService) GetCachedReport(host string) *model.SSLReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeScans[host]
}

func (s *ScannerService) GenerateTXT(report *model.SSLReport) string {
	var sb strings.Builder

	// 1. Crear un mapa para buscar certificados por ID rápidamente
	certMap := make(map[string]model.Cert)
	for _, c := range report.Certs {
		certMap[c.ID] = c
	}

	// Encabezado
	sb.WriteString("==========================================================\n")
	sb.WriteString(fmt.Sprintf("         REPORTE SSL: %s\n", strings.ToUpper(report.Host)))
	sb.WriteString("==========================================================\n\n")

	// Info General
	sb.WriteString(fmt.Sprintf("DOMINIO:  %s\n", report.Host))
	sb.WriteString(fmt.Sprintf("ESTADO:   %s\n", report.Status))
	if report.StatusMessage != "" {
		sb.WriteString(fmt.Sprintf("MENSAJE:  %s\n", report.StatusMessage))
	}

	// Conversión de fechas de Unix (ms) a legibles
	testTime := time.Unix(report.TestTime/1000, 0).Format("2006-01-02 15:04:05")
	sb.WriteString(fmt.Sprintf("FECHA:    %s\n", testTime))
	sb.WriteString("----------------------------------------------------------\n\n")

	// Iterar sobre Endpoints
	for i, ep := range report.Endpoints {
		sb.WriteString(fmt.Sprintf("ENDPOINT #%d\n", i+1))
		sb.WriteString(fmt.Sprintf("IP:          %s\n", ep.IPAddress))
		sb.WriteString(fmt.Sprintf("Server Name: %s\n", ep.ServerName))
		sb.WriteString(fmt.Sprintf("Grade:       %s\n", ep.Grade))

		sb.WriteString(fmt.Sprintf("ForwardSecrecy:  %v\n", ep.Details.ForwardSecrecy))
		sb.WriteString(fmt.Sprintf("Heartbleed:  %v\n", ep.Details.Heartbleed))
		sb.WriteString(fmt.Sprintf("VulnBeast:  %v\n", ep.Details.VulnBeast))

		// Protocolos soportados
		if len(ep.Details.Protocols) > 0 {
			sb.WriteString("Protocols:  ")
			for j, p := range ep.Details.Protocols {
				sb.WriteString(fmt.Sprintf("%s %s", p.Name, p.Version))
				if j < len(ep.Details.Protocols)-1 {
					sb.WriteString(", ")
				}
			}
			sb.WriteString("\n")
		}

		// Certificados (Usando las Cadenas y el Mapa)
		sb.WriteString("\nCHAIN  OF CERTIFICATES:\n")
		for _, chain := range ep.Details.CertChains {
			for _, certID := range chain.CertIds {
				if cert, ok := certMap[certID]; ok {
					sb.WriteString(fmt.Sprintf("  - Subject: %s\n", cert.Subject))
					sb.WriteString(fmt.Sprintf("    Alg:    %s (%s %d bits)\n", cert.SigAlg, cert.KeyAlg, cert.KeySize))

					expires := time.Unix(cert.NotAfter/1000, 0).Format("2006-01-02")
					sb.WriteString(fmt.Sprintf("    Expire: %s\n", expires))
					sb.WriteString("    --------------------------------------\n")
				}
			}
		}
		sb.WriteString("\n==========================================================\n")
	}

	return sb.String()
}

func (s *ScannerService) SaveToDisk() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.activeScans, "", " ")
	if err != nil {
		fmt.Printf("\nError when saving json: %v", err)
		return
	}

	//ahora en file
	errFile := os.WriteFile(dbFile, data, 0644)
	if errFile != nil {
		fmt.Printf("Error when saving to file %v", err)
	} else {
		fmt.Printf("Data saved en : %s", dbFile)
	}
}

func (s *ScannerService) LoadFromDisk() {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(dbFile)
	if err != nil {
		fmt.Printf("Err when loading data %v", err) //o es la primera vez que no ha guardado
		return
	}
	errLoad := json.Unmarshal(data, &s.activeScans)
	if errLoad != nil {
		fmt.Printf("Err when loading data %v", errLoad)
		return
	}
}

// por si mas adelante generar reporte de todos los sitios buscados en un solo .txt
func (s *ScannerService) GenerateFullReportTXT() string {
	// 1. Bloqueo de seguridad para lectura
	s.mu.RLock()
	defer s.mu.RUnlock()

	var fullBuilder strings.Builder

	fullBuilder.WriteString("##########################################################\n")
	fullBuilder.WriteString("          REPORTE GLOBAL DE TODOS LOS SITIOS\n")
	fullBuilder.WriteString(fmt.Sprintf("          Generado el: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	fullBuilder.WriteString("##########################################################\n\n")

	if len(s.activeScans) == 0 {
		fullBuilder.WriteString("No hay datos disponibles en el historial.\n")
		return fullBuilder.String()
	}

	// 2. Iterar sobre el mapa
	for _, report := range s.activeScans {

		reportText := s.GenerateTXT(report)

		fullBuilder.WriteString(reportText)
		fullBuilder.WriteString("\n\n") // Espacio entre reportes
		fullBuilder.WriteString("##########################################################\n\n")
	}

	return fullBuilder.String()
}
