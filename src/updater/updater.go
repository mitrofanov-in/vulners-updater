package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
)

////////// STRUCT COMBINATION ///////////////

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

////////// STRUCT SORT ////////////

type FiltersSort struct {
	ID           string `json:"id"`
	FilterName   string `json:"filterName"`
	Operator     string `json:"operator"`
	Type         string `json:"type"`
	IsPredefined bool   `json:"isPredefined"`
	Value        string `json:"value"`
}
type QuerySort struct {
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Context       string        `json:"context"`
	Status        int           `json:"status"`
	CreatedTime   int           `json:"createdTime"`
	ModifiedTime  int           `json:"modifiedTime"`
	Groups        []interface{} `json:"groups"`
	Type          string        `json:"type"`
	Tool          string        `json:"tool"`
	SourceType    string        `json:"sourceType"`
	StartOffset   int           `json:"startOffset"`
	EndOffset     int           `json:"endOffset"`
	Filters       []FiltersSort `json:"filters"`
	SortColumn    string        `json:"sortColumn"`
	SortDirection string        `json:"sortDirection"`
	VulnTool      string        `json:"vulnTool"`
}
type PluginSort struct {
	Query      QuerySort     `json:"query"`
	SourceType string        `json:"sourceType"`
	SortField  string        `json:"sortField"`
	SortDir    string        `json:"sortDir"`
	Columns    []interface{} `json:"columns"`
	Type       string        `json:"type"`
}

//var strHead

var url = "https://sc.interfax.ru/rest/analysis"

func HttpQueryPost(url string, jstr []byte) string {

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
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

func ConvertMap(body string) interface{} {

	var m map[string]interface{}
	json.Unmarshal([]byte(body), &m)
	f := m["response"]
	j := f.(map[string]interface{})
	u := j["results"]
	return u
}

func main() {

	arguments := os.Args
	levl := arguments[1]
	var y []interface{}

	client := &http.Client{}

	/////////////// TEST GET QUERY CHECK AUTHENTIFICATION //////////////
	//fmt.Println(strHead)
	req, err := http.NewRequest("GET", "https://sc.interfax.ru/rest/currentUser", nil)
	if err != nil {
		fmt.Println("Got error %s", err.Error())
	}
	req.Header.Set("x-apikey", strHead)
	response, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Got error %s", err.Error())
	}
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println(string(body))

	///////// POST QUERY CRITICAL /////////////

	jStr_crit := []byte(`{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"listvuln","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"firstSeen","filterName":"firstSeen","operator":"=","type":"vuln","isPredefined":true,"value":"0:7"},{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":true,"value":"4"}],"vulnTool":"listvuln"},"sourceType":"cumulative","columns":[],"type":"vuln"}`)
	body_crit := HttpQueryPost(url, jStr_crit)
	//fmt.Println(string(body_crit))

	u := ConvertMap(body_crit)

	for _, item := range u.([]interface{}) {
		fmt.Printf("%v", item.(map[string]interface{})["ip"])
	}

	PluginSortStruct := PluginSort{
		Query: QuerySort{
			Name:         "",
			Description:  "",
			Context:      "",
			Status:       -1,
			CreatedTime:  0,
			ModifiedTime: 0,
			Groups:       y,
			Type:         "vuln",
			Tool:         "sumid",
			SourceType:   "cumulative",
			StartOffset:  0,
			EndOffset:    50,
			Filters: []FiltersSort{
				{ID: "firstSeen", FilterName: "firstSeen", Operator: "=", Type: "vuln", IsPredefined: true, Value: "0:7"},
				{ID: "severity", FilterName: "severity", Operator: "=", Type: "vuln", IsPredefined: true, Value: levl},
			},
			SortColumn:    "severity",
			SortDirection: "desc",
			VulnTool:      "sumid",
		},
		SourceType: "cumulative",
		SortField:  "severity",
		SortDir:    "desc",
		Columns:    y,
		Type:       "vuln",
	}

	jsonDataSort, _ := json.Marshal(PluginSortStruct)

	jStr_medSort := []byte(jsonDataSort)

	///////////////////////// MUX ///////////////////////

	//fmt.Println(string(jStr_medSort))

	body_med := HttpQueryPost(url, jStr_medSort)

	u_med := ConvertMap(body_med)

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
					{ID: "severity", FilterName: "severity", Operator: "=", Type: "vuln", IsPredefined: true, Value: levl},
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
		u_med := ConvertMap(body_med)

		for _, item := range u_med.([]interface{}) {
			fmt.Printf("%v ", item.(map[string]interface{})["dnsName"])
			fmt.Printf("%v ", item.(map[string]interface{})["uuid"])

			DNSFileName := ""
			DNSFileName = fmt.Sprintf("%v", item.(map[string]interface{})["dnsName"])

			Uuid := ""
			Uuid = fmt.Sprintf("%v", item.(map[string]interface{})["uuid"])

			file, _ := os.Create(str + "_" + DNSFileName + ".txt")
			file.WriteString(DNSFileName + " ")
			file.WriteString(" " + Uuid)

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
						{ID: "severity", FilterName: "severity", Operator: "=", Type: "vuln", IsPredefined: true, Value: levl},
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
			u_vulndetail := ConvertMap(body_vulndetail)

			for _, item := range u_vulndetail.([]interface{}) {
				fmt.Printf("%v ", item.(map[string]interface{})["pluginText"])

				PlugTextW := ""
				PlugTextW = fmt.Sprintf("%v", item.(map[string]interface{})["pluginText"])
				reHtml := regexp.MustCompile("(?m)[\r\n]+^.*plugin_output.*$")
				re := regexp.MustCompile("(?m)[\r\n]+^.*Installed package.*$")
				resHtml := reHtml.ReplaceAllString(PlugTextW, "")
				fmt.Printf(resHtml)
				res := re.ReplaceAllString(resHtml, "")
				fmt.Printf(res)
				file.WriteString("" + res)
				defer file.Close()
			}

		}
	}

}
