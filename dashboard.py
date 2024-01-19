from dash import Dash, dcc, html, Input, Output, State, callback
import requests
import json

## BUILD APP ##
external_stylesheets = ['./assets/style.css']

app = Dash(__name__, external_stylesheets=external_stylesheets)

app.layout = html.Div([
    dcc.Input(id='input', 
              type='text', 
              placeholder='Search'),
    html.Button(id='submit-button', 
                n_clicks=0, 
                children='Submit'),
    html.Div(id='output-button')
])

@callback(Output('output-button', 'children'),
              Input('submit-button', 'n_clicks'),
              State('input', 'value')
              )

def update_output(n_clicks, input):
    return f'''
        The Button has been pressed {n_clicks} times,
        The 'Search' term is: "{input}"
    '''

if __name__ == '__main__':
    app.run(debug=True)