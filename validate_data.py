import pandas as pd

df = pd.read_csv("pypi_cleaned_dev_5000.csv")

# 1. Investigate extreme values
for column in [
    "package_age_days",
    "version_count",
    "total_uploads",
    "size"
]:
    print(f"\nTOP 5: {column}")
    print(
        df[["name", column]]
        .sort_values(column, ascending=False)
        .head(5)
        .to_string(index=False)
    )

# 2. Check invalid numerical values
print("\nNEGATIVE VALUES:")
for column in [
    "package_age_days",
    "version_count",
    "total_uploads",
    "size"
]:
    print(column, (df[column] < 0).sum())

# 3. Check timestamps
df["first_upload_time"] = pd.to_datetime(
    df["first_upload_time"],
    format="mixed",
    utc=True,
    errors="coerce"
)

df["latest_upload_time"] = pd.to_datetime(
    df["latest_upload_time"],
    format="mixed",
    utc=True,
    errors="coerce"
)

print("\nUNPARSEABLE TIMESTAMPS:")
print(df[
    ["first_upload_time", "latest_upload_time"]
].isna().sum())

print("\nEARLIEST PACKAGE:")
print(df["first_upload_time"].min())

print("\nLATEST UPLOAD:")
print(df["latest_upload_time"].max())

print("\nINVALID TIMESTAMP ORDER:")
print(
    (
        df["latest_upload_time"]
        < df["first_upload_time"]
    ).sum()
)

# 4. Verify package-age calculations
# Replace this with your actual data-collection date.
collection_date = pd.Timestamp(
    "2026-09-27", tz="UTC"
)

calculated_age = (
    collection_date - df["first_upload_time"]
).dt.days

age_difference = (
    df["package_age_days"] - calculated_age
).abs()

print("\nPACKAGE AGE MISMATCHES:")
print((age_difference > 1).sum())

# Compare stored ages against two possible definitions

# Definition A: Age at collection
age_at_collection = (
    collection_date - df["first_upload_time"]
).dt.days

# Definition B: Time between first and latest upload
release_history_days = (
    df["latest_upload_time"]
    - df["first_upload_time"]
).dt.days

print("\nPACKAGE AGE INVESTIGATION:")

print("Matches age at collection:")
print(
    (
        df["package_age_days"]
        == age_at_collection
    ).sum()
)

print("Matches release history duration:")
print(
    (
        df["package_age_days"]
        == release_history_days
    ).sum()
)

print("\nSAMPLE COMPARISON:")

print(pd.DataFrame({
    "package": df["name"].head(10),
    "stored_age": df["package_age_days"].head(10),
    "age_at_collection": age_at_collection.head(10),
    "release_history_days": release_history_days.head(10)
}).to_string(index=False))

# Investigate the original package-age reference date

inferred_dates = (
    df["first_upload_time"]
    + pd.to_timedelta(
        df["package_age_days"],
        unit="D"
    )
)

print("\nINFERRED COLLECTION DATES:")
print(inferred_dates.dt.date.value_counts().head(10))

# Compare stored ages with August 30, 2026
test_date = pd.Timestamp(
    "2026-08-30", tz="UTC"
)

test_ages = (
    test_date - df["first_upload_time"]
).dt.days

print("\nMATCHES USING AUGUST 30:")
print(
    (
        df["package_age_days"] == test_ages
    ).sum()
)

print("\nAGE DIFFERENCES:")
print(
    (
        df["package_age_days"] - test_ages
    ).value_counts().head(10)
)

reference_time = pd.Timestamp(
    "2026-09-13 12:00:00",
    tz="UTC"
)

expected_age = (
    reference_time - df["first_upload_time"]
).dt.days

print("\nMATCHES USING SEPTEMBER 13 NOON:")
print(
    (df["package_age_days"] == expected_age).sum()
)

print("\nAGE DIFFERENCES:")
print(
    (
        df["package_age_days"] - expected_age
    ).value_counts()
)