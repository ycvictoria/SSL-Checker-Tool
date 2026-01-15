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
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("API Error") // Error de servidor
	}
	defer resp.Body.Close()

	var report model.SSLReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, resp.StatusCode, err
	}
	for i := range report.Endpoints {
		addr := report.Endpoints[i].IPAddress
		geoUrl := fmt.Sprintf("http://ip-api.com/json/%s", addr)

		geoResp, err := http.Get(geoUrl)
		if err == nil {
			var geo struct {
				Country string `json:"country"`
				City    string `json:"city"`
			}
			json.NewDecoder(geoResp.Body).Decode(&geo)
			geoResp.Body.Close()

			report.Endpoints[i].Country = geo.Country
			report.Endpoints[i].City = geo.City

		}
	}

	return &report, resp.StatusCode, nil
}
