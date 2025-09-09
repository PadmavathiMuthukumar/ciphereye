import pandas as pd

df = pd.read_csv("./features/Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
print(df['label'].value_counts())  # Check if attack labels exist
