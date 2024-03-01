import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import requests

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the web page
app.layout = html.Div([
    html.H1("VirusTotal IP Lookup"),
    dcc.Input(id="ip-input", type="text", placeholder="Enter an IP Address"),
    html.Button("Submit", id="submit-button"),
    html.Div(id="result-output")
],style={
    "boarder": "1px solid",
    "margin": "auto"
    })

# Callback function to handle button click
@app.callback(
    Output("result-output", "children"),
    [Input("submit-button", "n_clicks")],
    [dash.dependencies.State("ip-input", "value")]
)
def display_virustotal_report(n_clicks, ip_address):
    if n_clicks and ip_address:
        try:
            api_key = "e550ee7dbd5b484158b66b7e73bf2ce927759dcca0abf450cfd718d4bc9c26e6"
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            response_json = response.json()

            if response.status_code == 200:
                data = response_json.get("data", {})
                attributes = data.get("attributes", {})
                country = attributes.get("country", "Unknown")
                last_analysis_results = attributes.get("last_analysis_results", {})

                # Create a table to display the results
                table_rows = []
                for engine, result in last_analysis_results.items():
                    table_rows.append(
                        html.Tr([
                            html.Td(engine),
                            html.Td(result["result"])
                        ])
                    )

                return html.Table([
                    html.Thead([
                        html.Tr([html.Th("Engine"), html.Th("Result")])
                    ]),
                    html.Tbody(table_rows)
                ])
            else:
                return "No information available for the IP address."
        except requests.exceptions.RequestException as e:
            return f"An error occurred during the request: {str(e)}"
    else:
        return ""

if __name__ == "__main__":
    app.run_server(debug=True)
