
import pandas as pd
from packaging.utils import canonicalize_name

# Step 1: Load your original dataset
df = pd.read_csv("pypi_raw_dev_5000.csv")

# Step 2: Standardize package names
df["normalized_name"] = (
    df["name"].astype(str).map(canonicalize_name)
)

# Step 3: Remove duplicate packages
df = df.drop_duplicates(subset=["normalized_name"])

# Step 4: Handle missing text fields
text_columns = [
    "summary", "author", "author_email",
    "maintainer", "maintainer_email",
    "license", "keywords", "home_page",
    "requires_python"
]

for col in text_columns:
    df[col] = df[col].fillna("").str.strip()

# Step 5: Convert timestamps
for col in ["first_upload_time", "latest_upload_time"]:
    df[col] = pd.to_datetime(
        df[col], utc=True, errors="coerce"
    )

# Step 6: Validate chronological consistency
invalid_dates = (
    df["first_upload_time"].isna()
    | df["latest_upload_time"].isna()
    | (df["latest_upload_time"] < df["first_upload_time"])
)

print("Rows with invalid dates:", invalid_dates.sum())

# Step 7: Recalculate metadata completeness flags
for source, flag in [
    ("summary", "has_summary"),
    ("author", "has_author"),
    ("maintainer", "has_maintainer"),
    ("home_page", "has_homepage")
]:
    df[flag] = df[source].ne("").astype(int)

# Step 8: Save a separate cleaned dataset
df.to_csv("pypi_cleaned_dev_5000.csv", index=False)

print("Cleaning complete:", df.shape)
