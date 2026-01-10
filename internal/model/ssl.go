package model

import "time"

type SSLReport struct {
	Host          string `json:"host"`
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage"`
	StartTime     int64  `json:"startTime"`
	TestTime      int64  `json:"testTime"`

	Endpoints []Endpoint `json:"endpoints"`
	Certs     []Cert     `json:"certs"`
}

type Endpoint struct {
	IPAddress  string          `json:"ipAddress"`
	Grade      string          `json:"grade"`
	ServerName string          `json:"serverName"`
	Duration   int64           `json:"duration"`
	Progress   int8            `json:"progress"`
	Details    EndpointDetails `json:"details"`
}

type EndpointDetails struct {
	CertChains     []CertChain `json:"certChains"`
	Protocols      []Protocol  `json:"protocols"`
	Heartbleed     bool        `json:"heartbleed"`
	VulnBeast      bool        `json:"vulnBeast"`
	ForwardSecrecy int         `json:"forwardSecrecy"`
}
type CertChain struct {
	ID      string   `json:"id"`
	CertIds []string `json:"certIds"` // Estos son los IDs que usaremos en el mapa
}

type Cert struct {
	ID               string   `json:"id"` // Importante para el mapa en el frontend
	Subject          string   `json:"subject"`
	IssuerLabel      string   `json:"issuerLabel"`
	SigAlg           string   `json:"sigAlg"`    // Algoritmo de firma
	KeyAlg           string   `json:"keyAlg"`    // RSA o EC
	KeySize          int      `json:"keySize"`   // 2048, 256, etc.
	NotBefore        int64    `json:"notBefore"` // Fecha emisión
	NotAfter         int64    `json:"notAfter"`  // Fecha vencimiento
	CommonNames      []string `json:"commonNames"`
	RevocationStatus int      `json:"revocationStatus"`
}

type Chain struct {
	Issues int `json:"issues"`
}

type Protocol struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (r *SSLReport) GetFormattedDate() string {
	return time.Unix(r.StartTime/1000, 0).Format("02/01/2006 15:04:05")
}

func (r *SSLReport) GetDuration() string {
	if r.TestTime <= r.StartTime {
		return "En progreso..."
	}
	duration := time.Duration(r.TestTime-r.StartTime) * time.Millisecond
	return duration.Round(time.Second).String()
}
