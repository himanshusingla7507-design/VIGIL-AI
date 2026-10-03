import os
import pandas as pd

print('cwd', os.getcwd())
print('files', os.listdir('.'))
for name in ['final_dataset_v2.csv', 'feature_names.pkl', 'phishing_model.pkl']:
    print(name, os.path.exists(name), os.path.getsize(name) if os.path.exists(name) else None)

df = pd.read_csv('final_dataset_v2.csv')
print('shape', df.shape)
print(df.head(3).to_dict(orient='records'))
print('columns', list(df.columns[:10]), '... total', len(df.columns))
print('label counts')
print(df.iloc[:, -1].value_counts(dropna=False).head())
