import pandas as pd

# Load cleaned dataset
df = pd.read_csv("pypi_cleaned_dev_5000.csv")

# 1. Check dataset dimensions
print("DATASET SHAPE:")
print(df.shape)

# 2. Check column names and data types
print("\nCOLUMN INFORMATION:")
df.info()

# 3. Check missing values
print("\nMISSING VALUES:")
print(df.isnull().sum())

# 4. Check duplicate package names
print("\nDUPLICATE PACKAGES:")
print(df["normalized_name"].duplicated().sum())

# 5. Examine numerical columns
print("\nNUMERICAL STATISTICS:")
print(df.describe())

# 6. Examine package age
print("\nPACKAGE AGE:")
print(df["package_age_days"].describe())