package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
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

//var strHead = "accesskey" + "=" + "9e3330df67be4330a21599ee66d87d9c" + "; " + "secretkey" + "=" + "d74e49ad9de64afbb0d76cc8c36d893a"

//// GLOBAL ////////

var tnblUser string = GoDotEnvVariable("tnblUser")
var tnblPassword string = GoDotEnvVariable("tnblPassword")

var strHead = "accesskey" + "=" + tnblUser + "; " + "secretkey" + "=" + tnblPassword

var url = "https://sc.interfax.ru/rest/analysis"

//////// POST QUERY SHEMA ////////

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

func GoDotEnvVariable(key string) string {

	// load .env file
	godotenv.Load(".env")
	return os.Getenv(key)
}

func main() {

	var y []interface{}

	client := &http.Client{}
	mux := http.NewServeMux()
	/////////////// TEST GET QUERY CHECK AUTHENTIFICATION //////////////
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

	/*
		////////////////////////////////// TEST READ JSON ////////////////////////////

		data, err := ioutil.ReadFile("./jsonSumid.json")
		if err != nil {
			fmt.Print(err)
		}

		var obj PluginSort

		err = json.Unmarshal(data, &obj)
		if err != nil {
			fmt.Println("error:", err)
		}

		fmt.Println(obj.Query.Tool)

		///////////////////////////////////// FUNDAMENT //////////////////////////////
	*/

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		request.ParseForm()
		levl := request.FormValue("vuln")

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
				//file.WriteString(DNSFileName + " ")
				//file.WriteString(" " + Uuid)

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
					res := re.ReplaceAllString(resHtml, "")
					res1 := strings.ReplaceAll(res, "Fixed package", "")
					res2 := strings.ReplaceAll(res1, ":", "")
					res3 := strings.ReplaceAll(res2, "\n", " ")
					res4 := strings.ReplaceAll(res3, "<plugin_output>", "")
					res5 := strings.ReplaceAll(res4, "           ", " ")
					res6 := strings.ReplaceAll(res5, "_", " ")
					parts := strings.Split(res6, " ")
					fmt.Printf("%q\n", parts)

					for k, _ := range parts {
						if k%2 == 1 {
							file.WriteString(parts[k] + " ")
							defer file.Close()
						} else {
							fmt.Println(parts[k])
						}
					}

				}
			}
		}
	})

	http.ListenAndServe(":8081", mux)

}

/*
parts := strings.Split(res5, "_")
					fmt.Printf("%q\n", parts)

					for k, _ := range parts {
						if k%2 == 0 {
							file.WriteString(parts[k])
							defer file.Close()
						} else {
							fmt.Println(parts[k])
						}
					}
*/

//file.WriteString(res5 + " ")
//defer file.Close()
