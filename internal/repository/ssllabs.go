package repository

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"ssl-checker/internal/model"
)

type SSLLabsRepo struct {
	APIURL string
}

func (r *SSLLabsRepo) FetchData(host string) (*model.SSLReport, int, error) {
	url := fmt.Sprintf("%s?host=%s&all=done", r.APIURL, host)
	//  Imprime en consola antes de la llamada
	log.Printf("📡 Llamando a SSL Labs: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var report model.SSLReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, resp.StatusCode, err
	}
	return &report, resp.StatusCode, nil
}
