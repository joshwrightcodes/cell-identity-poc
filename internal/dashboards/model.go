package dashboards

// The types in this file carry the JSON tags that Grafana reads. Field order fixes the order of the output.

// Data source UIDs from docker/grafana-datasources.yaml of the Grafana image.
const (
	DSPrometheus = "prometheus"
	DSLoki       = "loki"
)

// Dashboard is one Grafana dashboard. File names the output file under dashboards/.
type Dashboard struct {
	File          string     `json:"-"`
	UID           string     `json:"uid"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
	Editable      bool       `json:"editable"`
	GraphTooltip  int        `json:"graphTooltip"`
	Refresh       string     `json:"refresh,omitempty"`
	SchemaVersion int        `json:"schemaVersion"`
	Time          TimeRange  `json:"time"`
	Timezone      string     `json:"timezone,omitempty"`
	Links         []Link     `json:"links,omitempty"`
	Templating    Templating `json:"templating"`
	Panels        []Panel    `json:"panels"`
}

// TimeRange is the default time range of a dashboard.
type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Link is a dashboard link.
type Link struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Type        string `json:"type"`
	Icon        string `json:"icon,omitempty"`
	TargetBlank bool   `json:"targetBlank,omitempty"`
}

// Templating holds the variables of a dashboard.
type Templating struct {
	List []Variable `json:"list"`
}

// Variable is a query variable.
type Variable struct {
	Name       string      `json:"name"`
	Label      string      `json:"label,omitempty"`
	Type       string      `json:"type"`
	Datasource *Datasource `json:"datasource,omitempty"`
	Query      string      `json:"query"`
	Definition string      `json:"definition,omitempty"`
	Refresh    int         `json:"refresh"`
	Multi      bool        `json:"multi"`
	IncludeAll bool        `json:"includeAll"`
	Sort       int         `json:"sort"`
	Current    *Current    `json:"current,omitempty"`
}

// Current is the selected value of a variable.
type Current struct {
	Text  string `json:"text"`
	Value string `json:"value"`
}

// Datasource names a data source by type and UID.
type Datasource struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// GridPos places a panel on the 24-column grid.
type GridPos struct {
	H int `json:"h"`
	W int `json:"w"`
	X int `json:"x"`
	Y int `json:"y"`
}

// Panel is one Grafana panel.
type Panel struct {
	ID              int              `json:"id"`
	Type            string           `json:"type"`
	Title           string           `json:"title"`
	Description     string           `json:"description,omitempty"`
	GridPos         GridPos          `json:"gridPos"`
	Datasource      *Datasource      `json:"datasource,omitempty"`
	Targets         []Target         `json:"targets,omitempty"`
	FieldConfig     FieldConfig      `json:"fieldConfig"`
	Options         map[string]any   `json:"options,omitempty"`
	Transformations []map[string]any `json:"transformations,omitempty"`
}

// Target is one query of a panel. EventOnly marks a query that counts events and may return nothing before the first event.
type Target struct {
	RefID        string      `json:"refId"`
	Datasource   *Datasource `json:"datasource,omitempty"`
	Expr         string      `json:"expr"`
	Instant      bool        `json:"instant,omitempty"`
	Range        bool        `json:"range,omitempty"`
	Format       string      `json:"format,omitempty"`
	LegendFormat string      `json:"legendFormat,omitempty"`
	QueryType    string      `json:"queryType,omitempty"`
	EventOnly    bool        `json:"eventOnly,omitempty"`
}

// FieldConfig holds the defaults and the overrides of a panel.
type FieldConfig struct {
	Defaults  FieldDefaults `json:"defaults"`
	Overrides []Override    `json:"overrides"`
}

// FieldDefaults holds the field settings that apply to every series.
type FieldDefaults struct {
	Unit       string           `json:"unit,omitempty"`
	Decimals   *int             `json:"decimals,omitempty"`
	Min        *float64         `json:"min,omitempty"`
	Max        *float64         `json:"max,omitempty"`
	Color      map[string]any   `json:"color,omitempty"`
	Thresholds *Thresholds      `json:"thresholds,omitempty"`
	Mappings   []map[string]any `json:"mappings,omitempty"`
	Custom     map[string]any   `json:"custom,omitempty"`
}

// Thresholds is a list of threshold steps.
type Thresholds struct {
	Mode  string          `json:"mode"`
	Steps []ThresholdStep `json:"steps"`
}

// ThresholdStep is one threshold. The first step has a nil Value.
type ThresholdStep struct {
	Color string   `json:"color"`
	Value *float64 `json:"value"`
}

// Override changes the field settings of the series that match.
type Override struct {
	Matcher    FieldMatcher `json:"matcher"`
	Properties []Property   `json:"properties"`
}

// FieldMatcher selects the series of an override.
type FieldMatcher struct {
	ID      string `json:"id"`
	Options string `json:"options"`
}

// Property is one field setting of an override.
type Property struct {
	ID    string `json:"id"`
	Value any    `json:"value"`
}

// RuleFile is the Grafana alert rule provisioning file.
type RuleFile struct {
	APIVersion int         `json:"apiVersion"`
	Groups     []RuleGroup `json:"groups"`
}

// RuleGroup is a group of alert rules with one evaluation interval.
type RuleGroup struct {
	OrgID    int    `json:"orgId"`
	Name     string `json:"name"`
	Folder   string `json:"folder"`
	Interval string `json:"interval"`
	Rules    []Rule `json:"rules"`
}

// Rule is one alert rule.
type Rule struct {
	UID          string            `json:"uid"`
	Title        string            `json:"title"`
	Condition    string            `json:"condition"`
	Data         []RuleQuery       `json:"data"`
	NoDataState  string            `json:"noDataState"`
	ExecErrState string            `json:"execErrState"`
	For          string            `json:"for"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// RuleQuery is one query or expression of a rule. Model holds the fields that Grafana reads, such as expr.
type RuleQuery struct {
	RefID             string         `json:"refId"`
	RelativeTimeRange *RelativeRange `json:"relativeTimeRange,omitempty"`
	DatasourceUID     string         `json:"datasourceUid"`
	Model             map[string]any `json:"model"`
}

// RelativeRange is the range of a rule query, in seconds before now.
type RelativeRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}
