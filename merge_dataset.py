import pandas as pd

files = [
    "phishing_url_dataset_unique.csv",
    "malicious_phish.csv",
    "PhiUSIIL_Phishing_URL_Dataset.csv",
    "dataset_phishing.csv",
    "fixed_dataset_phishing.csv"
]

dfs = []

for file in files:
    print(f"Processing: {file}")
    
    try:
        df = pd.read_csv(file)
    except:
        print(f"❌ Skipped (missing): {file}")
        continue

    # Normalize column names
    df.columns = df.columns.str.lower()

    # Find URL column
    url_col = None
    for col in df.columns:
        if "url" in col:
            url_col = col
            break

    # Find label column
    label_col = None
    for col in df.columns:
        if col in ["label", "class", "result", "type", "status"]:
            label_col = col
            break

    if url_col is None or label_col is None:
        print(f"❌ Skipped (bad format): {file}")
        continue

    temp = df[[url_col, label_col]].copy()
    temp.columns = ["url", "label"]

    dfs.append(temp)

# 🔥 Merge ALL datasets correctly
final_df = pd.concat(dfs, ignore_index=True)

# Clean
final_df = final_df.dropna()
final_df = final_df.drop_duplicates()

# Normalize labels
final_df["label"] = final_df["label"].astype(str).str.lower()
final_df["label"] = final_df["label"].map({
    "legitimate": 0,
    "benign": 0,
    "safe": 0,
    "0": 0,
    "phishing": 1,
    "malicious": 1,
    "1": 1
})

final_df = final_df.dropna()

print("📊 Final dataset size:", len(final_df))
print(final_df["label"].value_counts())

# Save
final_df.to_csv("final_dataset.csv", index=False)

print("✅ final_dataset.csv READY")