# dashboard.py
import dash
from dash import dcc, html, dash_table
import pandas as pd
import plotly.express as px

# ---------------------------
# Load model results CSV
# ---------------------------
CSV_FILE = "./dashboard_csvfiles/model_results.csv"
df = pd.read_csv(CSV_FILE)

# ---------------------------
# Initialize Dash app
# ---------------------------
app = dash.Dash(__name__)
app.title = "Model Evaluation Dashboard"

# ---------------------------
# Create a bar chart for metrics
# ---------------------------
metrics = ["Accuracy", "Precision", "Recall", "F1-score"]
fig = px.bar(
    df.melt(id_vars=["Model"], value_vars=metrics),
    x="Model",
    y="value",
    color="variable",
    barmode="group",
    text="value",
    title="Model Performance Metrics",
    labels={"value": "Score", "variable": "Metric"}
)
fig.update_traces(texttemplate="%{text:.4f}", textposition="outside")
fig.update_layout(yaxis=dict(range=[0, 1]))  # all metrics are between 0 and 1

# ---------------------------
# Layout
# ---------------------------
app.layout = html.Div([
    html.H1("AI Model Performance Dashboard", style={"textAlign": "center"}),

    html.H2("Model Metrics Table"),
    dash_table.DataTable(
        df.to_dict('records'),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_cell={'textAlign': 'center'},
        style_header={'fontWeight': 'bold'},
        style_table={'width': '70%', 'margin': 'auto'},
    ),

    html.H2("Model Metrics Comparison"),
    dcc.Graph(figure=fig)
], style={"fontFamily": "Arial, sans-serif", "margin": "20px"})

# ---------------------------
# Run the app
# ---------------------------
if __name__ == '__main__':
    app.run(debug=True)
