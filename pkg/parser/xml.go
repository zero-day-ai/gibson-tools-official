package parser

import (
	"encoding/xml"
	"fmt"
)

// ParseXML parses XML output into a structured type using generics
func ParseXML[T any](data []byte) (*T, error) {
	var result T
	if err := xml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	return &result, nil
}

// NmapRun represents nmap XML output structure
type NmapRun struct {
	XMLName   xml.Name   `xml:"nmaprun"`
	Scanner   string     `xml:"scanner,attr"`
	Args      string     `xml:"args,attr"`
	Start     int64      `xml:"start,attr"`
	StartStr  string     `xml:"startstr,attr"`
	Version   string     `xml:"version,attr"`
	Hosts     []NmapHost `xml:"host"`
	RunStats  NmapStats  `xml:"runstats"`
}

// NmapHost represents a host in nmap output
type NmapHost struct {
	StartTime int64         `xml:"starttime,attr"`
	EndTime   int64         `xml:"endtime,attr"`
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     NmapPorts     `xml:"ports"`
	OS        NmapOS        `xml:"os"`
	Uptime    NmapUptime    `xml:"uptime"`
	Distance  NmapDistance  `xml:"distance"`
	Scripts   []NmapScript  `xml:"hostscript>script"`
}

// NmapStatus represents host status
type NmapStatus struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

// NmapAddress represents a host address
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

// NmapHostname represents a hostname
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPorts represents port scan results
type NmapPorts struct {
	ExtraPorts []NmapExtraPort `xml:"extraports"`
	Ports      []NmapPort      `xml:"port"`
}

// NmapExtraPort represents summary of filtered/closed ports
type NmapExtraPort struct {
	State   string             `xml:"state,attr"`
	Count   int                `xml:"count,attr"`
	Reasons []NmapExtraReason  `xml:"extrareasons"`
}

// NmapExtraReason represents reasons for extraports
type NmapExtraReason struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

// NmapPort represents a single port
type NmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    NmapState    `xml:"state"`
	Service  NmapService  `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

// NmapState represents port state
type NmapState struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

// NmapService represents service detection results
type NmapService struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr,omitempty"`
	Version    string `xml:"version,attr,omitempty"`
	ExtraInfo  string `xml:"extrainfo,attr,omitempty"`
	Method     string `xml:"method,attr"`
	Conf       int    `xml:"conf,attr"`
	CPE        []string `xml:"cpe"`
}

// NmapScript represents NSE script output
type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// NmapOS represents OS detection results
type NmapOS struct {
	PortUsed []NmapPortUsed `xml:"portused"`
	OSMatch  []NmapOSMatch  `xml:"osmatch"`
}

// NmapPortUsed represents ports used for OS detection
type NmapPortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortID int    `xml:"portid,attr"`
}

// NmapOSMatch represents OS match results
type NmapOSMatch struct {
	Name     string          `xml:"name,attr"`
	Accuracy int             `xml:"accuracy,attr"`
	Line     int             `xml:"line,attr"`
	OSClass  []NmapOSClass   `xml:"osclass"`
}

// NmapOSClass represents OS classification
type NmapOSClass struct {
	Type     string   `xml:"type,attr"`
	Vendor   string   `xml:"vendor,attr"`
	OSFamily string   `xml:"osfamily,attr"`
	OSGen    string   `xml:"osgen,attr,omitempty"`
	Accuracy int      `xml:"accuracy,attr"`
	CPE      []string `xml:"cpe"`
}

// NmapUptime represents system uptime
type NmapUptime struct {
	Seconds  int    `xml:"seconds,attr"`
	LastBoot string `xml:"lastboot,attr"`
}

// NmapDistance represents network distance
type NmapDistance struct {
	Value int `xml:"value,attr"`
}

// NmapStats represents run statistics
type NmapStats struct {
	Finished NmapFinished `xml:"finished"`
	Hosts    NmapHosts    `xml:"hosts"`
}

// NmapFinished represents completion status
type NmapFinished struct {
	Time     int64  `xml:"time,attr"`
	TimeStr  string `xml:"timestr,attr"`
	Elapsed  float64 `xml:"elapsed,attr"`
	Summary  string `xml:"summary,attr"`
	Exit     string `xml:"exit,attr"`
}

// NmapHosts represents host statistics
type NmapHosts struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}
