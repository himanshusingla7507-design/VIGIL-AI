import pandas as pd

df = pd.read_csv("dataset_phishing.csv")

df['label'] = df['status'].map({
    "legitimate": 0,
    "phishing": 1
})

df[['url','label']].to_csv("fixed_dataset_phishing.csv", index=False)

print("✅ fixed_dataset_phishing.csv ready")