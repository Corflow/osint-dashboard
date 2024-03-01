import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import requests

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the web page
app.layout = html.Div([
    html.H1("IP Analysis Dashboard"),
    dcc.Input(id="ip-input", type="text", placeholder="Enter an IP Address"),
    html.Button("Submit", id="submit-button"),
    html.Div(id="result-output")
])

# Function to get VirusTotal report
def get_virustotal_report(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": "e550ee7dbd5b484158b66b7e73bf2ce927759dcca0abf450cfd718d4bc9c26e6"}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to get Hybrid Analysis report
def get_hybrid_analysis_report(ip_address):
    url = f"https://www.hybrid-analysis.com/api/v2/search/hash?query={ip_address}"
    headers = {"api-key": "ce1lic4r4cc0fca9cxwl3alw51eeee9268qtlc0nc2ca2c52750foge09cbe2b68"}
    response = requests.get(url, headers=headers)
    return response.json()

# Callback function to handle button click
@app.callback(
    Output("result-output", "children"),
    [Input("submit-button", "n_clicks")],
    [dash.dependencies.State("ip-input", "value")]
)
def display_reports(n_clicks, ip_address):
    if n_clicks and ip_address:
        vt_report = get_virustotal_report(ip_address)
        ha_report = get_hybrid_analysis_report(ip_address)

        if vt_report and ha_report:
            vt_table = create_report_table(vt_report, "VirusTotal")
            ha_table = create_report_table(ha_report, "Hybrid Analysis")

            return html.Div([vt_table, ha_table])
        else:
            return "No information available for the IP address."
    else:
        return ""

# Function to create a report table
def create_report_table(report, source):
    table_rows = []
    for key, value in report.items():
        if isinstance(value, dict):
            value = "\n".join([f"{k}: {v}" for k, v in value.items()])
        table_rows.append(
            html.Tr([
                html.Td(key),
                html.Td(value)
            ])
        )

    return html.Div([
        html.H3(f"{source} Report"),
        html.Table([
            html.Thead([
                html.Tr([html.Th("Attribute"), html.Th("Value")])
            ]),
            html.Tbody(table_rows)
        ])
    ])

if __name__ == "__main__":
    app.run_server(debug=True)
