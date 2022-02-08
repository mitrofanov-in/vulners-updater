package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type Filters struct {
	ID           string `json:"id"`
	FilterName   string `json:"filterName"`
	Operator     string `json:"operator"`
	Type         string `json:"type"`
	IsPredefined bool   `json:"isPredefined"`
	Value        string `json:"value"`
}
type Query struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Context      string        `json:"context"`
	Status       int           `json:"status"`
	CreatedTime  int           `json:"createdTime"`
	ModifiedTime int           `json:"modifiedTime"`
	Groups       []interface{} `json:"groups"`
	Type         string        `json:"type"`
	Tool         string        `json:"tool"`
	SourceType   string        `json:"sourceType"`
	StartOffset  int           `json:"startOffset"`
	EndOffset    int           `json:"endOffset"`
	Filters      []Filters     `json:"filters"`
	VulnTool     string        `json:"vulnTool"`
}

type Plugin struct {
	Query      Query         `json:"query"`
	SourceType string        `json:"sourceType"`
	Columns    []interface{} `json:"columns"`
	Type       string        `json:"type"`
}

//var strHead

var url = "https://sc.interfax.ru/rest/analysis"

func HttpQueryPost(url string, jstr []byte) string {
	client := &http.Client{}
	/*
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	*/

	req_http, _ := http.NewRequest("POST", url, bytes.NewBuffer(jstr))
	req_http.Header.Set("x-apikey", strHead)
	resp_http, err := client.Do(req_http)
	if err != nil {
		panic(err)
	}
	defer resp_http.Body.Close()

	body, _ := ioutil.ReadAll(resp_http.Body)
	return string(body)

}

var cookie_auth []*http.Cookie

func main() {

	client := &http.Client{}

	fmt.Println(strHead)

	req, err := http.NewRequest("GET", "https://sc.interfax.ru/rest/currentUser", nil)
	if err != nil {
		fmt.Println("Got error %s", err.Error())
	}

	req.Header.Set("x-apikey", strHead)

	response, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Got error %s", err.Error())
	}

	cookie_auth = response.Cookies()

	for _, c := range cookie_auth {
		fmt.Println(c.Name, c.Value)
	}

	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println(string(body))

	///////// POST QUERY /////////////

	jStr_crit := []byte(`{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"listvuln","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"firstSeen","filterName":"firstSeen","operator":"=","type":"vuln","isPredefined":true,"value":"0:7"},{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":true,"value":"4"}],"vulnTool":"listvuln"},"sourceType":"cumulative","columns":[],"type":"vuln"}`)

	//req_lgn.Header.Set("Content-Type", "application/json")

	body_crit := HttpQueryPost(url, jStr_crit)
	fmt.Println(string(body_crit))

	var m map[string]interface{}
	json.Unmarshal([]byte(body_crit), &m)

	//if bodyStatus_stat == 200 {
	f := m["response"]
	j := f.(map[string]interface{})
	u := j["results"]

	for _, item := range u.([]interface{}) {
		fmt.Printf("%v", item.(map[string]interface{})["ip"])
	}

	//jStr_med := []byte(`{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"listvuln","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"firstSeen","filterName":"firstSeen","operator":"=","type":"vuln","isPredefined":true,"value":"0:7"},{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":true,"value":"2"}],"vulnTool":"listvuln"},"sourceType":"cumulative","columns":[],"type":"vuln"}`)
	//jStr_med := []byte(`{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"uuid","filterName":"uuid","operator":"=","type":"vuln","isPredefined":true,"value":"0a35e414-39ec-49eb-9d36-b22c2735df11"},{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":true,"value":"157353"},{"id":"port","filterName":"port","operator":"=","type":"vuln","isPredefined":true,"value":"0"},{"id":"repository","filterName":"repository","operator":"=","type":"vuln","isPredefined":true,"value":[{"id":"2"}]},{"id":"firstSeen","filterName":"firstSeen","operator":"=","type":"vuln","isPredefined":true,"value":"0:7"},{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":true,"value":"2"}],"vulnTool":"vulndetails"},"sourceType":"cumulative","columns":[],"type":"vuln"}`)
	jStr_med := []byte(`{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumid","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"firstSeen","filterName":"firstSeen","operator":"=","type":"vuln","isPredefined":true,"value":"0:7"},{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":true,"value":"2"}],"sortColumn":"severity","sortDirection":"desc","vulnTool":"sumid"},"sourceType":"cumulative","sortField":"severity","sortDir":"desc","columns":[],"type":"vuln"}`)
	req_med, _ := http.NewRequest("POST", "https://sc.interfax.ru/rest/analysis", bytes.NewBuffer(jStr_med))
	//req_lgn.Header.Set("Content-Type", "application/json")

	req_med.Header.Set("x-apikey", strHead)

	resp_med, err := client.Do(req_med)
	if err != nil {
		panic(err)
	}

	defer resp_med.Body.Close()
	body_med, _ := ioutil.ReadAll(resp_med.Body)
	//fmt.Println(string(body_med))

	var m_med map[string]interface{}
	json.Unmarshal([]byte(body_med), &m_med)

	//if bodyStatus_stat == 200 {
	f_med := m_med["response"]
	j_med := f_med.(map[string]interface{})
	u_med := j_med["results"]

	var y []interface{}

	for _, item_med := range u_med.([]interface{}) {
		fmt.Printf("%v ", item_med.(map[string]interface{})["pluginID"])

		str := ""
		str = fmt.Sprintf("%v", item_med.(map[string]interface{})["pluginID"])

		plugStruct := Plugin{
			Query: Query{
				Name:         "",
				Description:  "",
				Context:      "",
				Status:       -1,
				CreatedTime:  0,
				ModifiedTime: 0,
				Groups:       y,
				Type:         "vuln",
				Tool:         "listvuln",
				SourceType:   "cumulative",
				StartOffset:  0,
				EndOffset:    50,
				Filters: []Filters{
					{ID: "pluginID", FilterName: "pluginID", Operator: "=", Type: "vuln", IsPredefined: true, Value: str},
					{ID: "firstSeen", FilterName: "firstSeen", Operator: "=", Type: "vuln", IsPredefined: true, Value: "0:7"},
					{ID: "severity", FilterName: "severity", Operator: "=", Type: "vuln", IsPredefined: true, Value: "2"},
				},
				VulnTool: "listvuln",
			},
			SourceType: "cumulative",
			Columns:    y,
			Type:       "vuln",
		}

		jsonData, _ := json.Marshal(plugStruct)

		jStr_med := []byte(jsonData)

		///////////////////////////////////// POST STRING ////////////////////////////////////

		body_med := HttpQueryPost(url, jStr_med)
		var m_med map[string]interface{}
		json.Unmarshal([]byte(body_med), &m_med)
		//fmt.Println(string(body_med))

		f_med := m_med["response"]
		j_med := f_med.(map[string]interface{})
		u_med := j_med["results"]

		for _, item := range u_med.([]interface{}) {
			fmt.Printf("%v ", item.(map[string]interface{})["dnsName"])
			fmt.Printf("%v ", item.(map[string]interface{})["uuid"])

			DNSFileName := ""
			DNSFileName = fmt.Sprintf("%v", item.(map[string]interface{})["dnsName"])

			Uuid := ""
			Uuid = fmt.Sprintf("%v", item.(map[string]interface{})["uuid"])

			file, _ := os.Create(str + "_" + DNSFileName + ".txt")
			file.WriteString(DNSFileName + " ")
			file.WriteString(Uuid)

			plugStructDetail := Plugin{
				Query: Query{
					Name:         "",
					Description:  "",
					Context:      "",
					Status:       -1,
					CreatedTime:  0,
					ModifiedTime: 0,
					Groups:       y,
					Type:         "vuln",
					Tool:         "vulndetails",
					SourceType:   "cumulative",
					StartOffset:  0,
					EndOffset:    50,
					Filters: []Filters{
						{ID: "uuid", FilterName: "uuid", Operator: "=", Type: "vuln", IsPredefined: true, Value: Uuid},
						{ID: "pluginID", FilterName: "pluginID", Operator: "=", Type: "vuln", IsPredefined: true, Value: str},
						{ID: "port", FilterName: "port", Operator: "=", Type: "vuln", IsPredefined: true, Value: "0"},
						{ID: "firstSeen", FilterName: "firstSeen", Operator: "=", Type: "vuln", IsPredefined: true, Value: "0:7"},
						{ID: "severity", FilterName: "severity", Operator: "=", Type: "vuln", IsPredefined: true, Value: "2"},
					},
					VulnTool: "vulndetails",
				},
				SourceType: "cumulative",
				Columns:    y,
				Type:       "vuln",
			}

			jsonDataVulnDetail, _ := json.Marshal(plugStructDetail)

			jStr_vulndetail := []byte(jsonDataVulnDetail)
			//fmt.Println(string(jStr_vulndetail))

			body_vulndetail := HttpQueryPost(url, jStr_vulndetail)
			var m_vulndetail map[string]interface{}
			json.Unmarshal([]byte(body_vulndetail), &m_vulndetail)
			//fmt.Println(string(body_vulndetail))
			f_vulndetail := m_vulndetail["response"]
			j_vulndetail := f_vulndetail.(map[string]interface{})
			u_vulndetail := j_vulndetail["results"]

			for _, item := range u_vulndetail.([]interface{}) {
				fmt.Printf("%v ", item.(map[string]interface{})["pluginText"])

				PlugTextW := ""
				PlugTextW = fmt.Sprintf("%v", item.(map[string]interface{})["pluginText"])
				file.WriteString(PlugTextW)
				defer file.Close()
			}

		}
	}

}
