import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from _paths import DEV_DATA_DIR, FIGURES_DIR

df = pd.read_csv(DEV_DATA_DIR / "pypi_cleaned_dev_5000.csv")

sns.set_theme(style="whitegrid")

fig, axes = plt.subplots(2, 2, figsize=(12, 9))

# Package age
sns.histplot(
    df["package_age_days"],
    bins=40,
    ax=axes[0, 0]
)
axes[0, 0].set_title("Package Age Distribution")

# Version count
sns.boxplot(
    x=df["version_count"],
    ax=axes[0, 1]
)
axes[0, 1].set_title("Version Count")

# Package size
sns.histplot(
    df["size"],
    bins=40,
    log_scale=True,
    ax=axes[1, 0]
)
axes[1, 0].set_title("Package Size Distribution")

# Metadata completeness
metadata = [
    "has_summary",
    "has_author",
    "has_maintainer",
    "has_homepage"
]

df[metadata].mean().mul(100).plot(
    kind="bar",
    ax=axes[1, 1]
)
axes[1, 1].set_title("Metadata Completeness (%)")
axes[1, 1].set_ylim(0, 100)

plt.tight_layout()
FIGURES_DIR.mkdir(parents=True, exist_ok=True)
plt.savefig(FIGURES_DIR / "eda_visualizations.png", dpi=300)
plt.show()
