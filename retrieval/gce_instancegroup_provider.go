package retrieval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"

	clientmodel "github.com/prometheus/client_golang/model"

	"github.com/prometheus/prometheus/config"
)

var (
	gceDiscoveryFailuresCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:	  "gce_discovery_failures_total",
			Help:	  "The number of GCE backend service discovery failures.",
		})

	gceDiscoveryClientBackends = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name: "gce_targets",
			Help: "Number of instances discovered for each instance group.",
		},
		[]string{"zone", "instance_group"})
)

func init() {
	prometheus.MustRegister(gceDiscoveryFailuresCount)
	prometheus.MustRegister(gceDiscoveryClientBackends)
}

type _gceLBBackend struct {
	instanceName string
	resourceUrl string
}

type gceInstanceGroupProvider struct {
	job config.JobConfig

	apiClient *http.Client
	authHeader string
	tokenExpires time.Time

	backends map[string]*_gceLBBackend

	globalLabels clientmodel.LabelSet
	targets	  []Target
}

// NewGceInstanceGroupProvider constructs a new gceInstanceGroupProvider for a job.
func NewGceInstanceGroupProvider(job config.JobConfig, globalLabels clientmodel.LabelSet) *gceInstanceGroupProvider {
	lb := &gceInstanceGroupProvider{
		backends: make(map[string]*_gceLBBackend),
		job:			 job,
	 	globalLabels:	globalLabels,
	}
	if len(job.GetGceDiscovery().GetApiProxyUrl()) != 0 {
		proxyUrl, _ := url.Parse(job.GetGceDiscovery().GetApiProxyUrl())
		lb.apiClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}
	} else {
		lb.apiClient = &http.Client{}
	}
	return lb
}

// Per: https://cloud.google.com/compute/docs/authentication
func (lb *gceInstanceGroupProvider) refreshAccessToken() error {
	if len(lb.authHeader) > 0 && lb.tokenExpires.After(time.Now()) {
		// Still valid.
		return nil
	}

	lb.authHeader = ""

	accessTokenUrl :=
		fmt.Sprintf("http://metadata/computeMetadata/v1/instance/service-accounts/%s/token",
			lb.job.GetGceDiscovery().GetServiceAccount())
	req, _ := http.NewRequest("GET", accessTokenUrl, nil)
	req.Header.Add("Metadata-Flavor", "Google" )
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Read token response: %s", err)
		return err
	}
	// {"access_token":"ya29.XAE9ZoxvmWXrdqsfjd9ORctCcafAwOZpMKclr2yfIMAGZBxmpSRZbKXK","expires_in":3599,"token_type":"Bearer"}

	var tokenResponse struct{
		AccessToken string	  `json:"access_token"`
		ExpiresInSec int		`json:"expires_in"`
		TokenType string		`json:"token_type"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		glog.Errorf("Parse token response: %s", err)
		return  err
	}

	token := tokenResponse.AccessToken

	if len(token) == 0 {
		return fmt.Errorf("Empty access token.")
	}

	lb.authHeader = fmt.Sprintf("%s %s", tokenResponse.TokenType, token)
	lb.tokenExpires = time.Now().Add(time.Duration(tokenResponse.ExpiresInSec) * time.Second)

	glog.Infof("**** Refreshed %s access token, expires in %d sec", tokenResponse.TokenType, tokenResponse.ExpiresInSec)

	return nil
}

type _gceApiErrorJson struct {
	Code int							`json:"code"`
	Message string					  `json:"message"`
}

type _gceApiResponseJson struct {
	Error *_gceApiErrorJson				`json:"error"`
}

type _gceLabelJson struct {
	Key string						`json:"key"`
	Value string					`json:"value"`
}
type _gceEndpointJson struct {
	Name string						`json:"name"`
	Port int						`json:"port"`
}

// Known as "resourceView" in the v1beta2 API.
type _gceInstanceGroupJson struct {
	_gceApiResponseJson

	Kind string						`json:"kind"`
	Name string						`json:"name"`
	Description string				`json:"name"`
	Size int						`json:"size"`
	CreationTimestamp string		`json:"creationTimestamp"`
	Resources []string				`json:"resources"`
	Id string						`json:"id"`
	SelfLink string				 	`json:"selfLink"`
	Labels []_gceLabelJson			`json:"labels"`
	Endpoints []_gceEndpointJson	`json:"endpoints"`
	Network string					`json:"network"`
	Fingerprint string				`json:"fingerprint"`
}

func (lb *gceInstanceGroupProvider) getInstanceGroupResources(zone, instance_group string) ([]string, error) {
	getInstanceGroupUrl :=
		fmt.Sprintf("https://www.googleapis.com/resourceviews/v1beta2/projects/%s/zones/%s/resourceViews/%s",
			lb.job.GetGceDiscovery().GetProject(),
			zone, instance_group)

	req, _ := http.NewRequest("GET", getInstanceGroupUrl, nil)
	req.Header.Add("Authorization", lb.authHeader)
	resp, err := lb.apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Read instance group %s/%s: %s", zone, instance_group, err)
		return nil, err
	}

	var group _gceInstanceGroupJson
	err = json.Unmarshal(body, &group)
	if err != nil {
		glog.Errorf("Parse instance group: %s", err)
		return nil, err
	}

	if group.Error != nil && len(group.Error.Message) > 0 {
		return nil, errors.New(group.Error.Message)
	}

	return group.Resources, nil
}

func (lb *gceInstanceGroupProvider) getBackendList(zone, instance_group string) ([]*_gceLBBackend, error) {
	// Get access token.
	err := lb.refreshAccessToken()
	if err != nil {
		return nil, err
	}

	resources, err := lb.getInstanceGroupResources(zone, instance_group)
	if err != nil {
		return nil, err
	}

	var backends []*_gceLBBackend
	for _, resource := range resources {
		shortName := resource[strings.LastIndex(resource, "/") + 1:]
		backends = append(backends, &_gceLBBackend{
			instanceName: shortName,
			resourceUrl: resource,
		})
	}

	return backends, nil
}

func (lb *gceInstanceGroupProvider) Targets() ([]Target, error) {
	var err error
	defer func() {
		if err != nil {
			gceDiscoveryFailuresCount.Inc()
		}
	}()

	targets := make([]Target, 0, len(lb.targets))

	for _, group := range(lb.job.GetGceDiscovery().Groups) {
		baseLabels := clientmodel.LabelSet{
			clientmodel.JobLabel: clientmodel.LabelValue(lb.job.GetName()),
		}
		for n, v := range lb.globalLabels {
			baseLabels[n] = v
		}
		baseLabels[clientmodel.LabelName("zone")] = clientmodel.LabelValue(group.GetZone())
		baseLabels[clientmodel.LabelName("instance_group")] = clientmodel.LabelValue(group.GetGroupName())

		newBackendList, err := lb.getBackendList(group.GetZone(), group.GetGroupName())
		if err != nil {
			glog.Warningf("Failed to fetch backend list: %s", err)
			return nil, err
		}
		exportLabels := prometheus.Labels{
			"zone":group.GetZone(),
			"instance_group":group.GetGroupName(),
		}
		gceDiscoveryClientBackends.With(exportLabels).Set(float64(len(newBackendList)))

		endpoint := &url.URL{
			Scheme: "http",
			Path:   lb.job.GetMetricsPath(),
		}
		var domainSuffix string
		if len(lb.job.GetGceDiscovery().GetAppendDomain()) > 0 {
			domainSuffix = fmt.Sprintf(".%s", lb.job.GetGceDiscovery().GetAppendDomain())
		}
		for _, backend := range newBackendList {
			endpoint.Host = fmt.Sprintf("%s%s:%d",
				backend.instanceName,
				domainSuffix,
				lb.job.GetGceDiscovery().GetPort())
			t := NewTarget(endpoint.String(), lb.job.ScrapeTimeout(), baseLabels)
			targets = append(targets, t)
		}
	}

	lb.targets = targets
	return targets, nil
}
